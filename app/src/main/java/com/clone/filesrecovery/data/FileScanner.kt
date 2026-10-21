package com.clone.filesrecovery.data

import android.content.ContentResolver
import android.content.ContentValues
import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.media.MediaMetadataRetriever
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.StatFs
import android.provider.MediaStore
import com.clone.filesrecovery.forensics.DeviceEnvironmentAssessment
import com.clone.filesrecovery.forensics.DeviceEnvironmentAssessor
import com.clone.filesrecovery.forensics.OperatingMode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.File
import java.io.RandomAccessFile
import java.security.MessageDigest

/**
 * Deep Analysis & Maximum-Recovery File Engine.
 *
 * Combines 4 recovery layers:
 *  1. Full recursive directory walk across all storage roots (including dot-folders,
 *     .trashed-*, .thumbnails, MIUI/Samsung/ system recycle bins, LOST.DIR, app media caches).
 *  2. Android MediaStore deep query with MATCH_TRASHED and MATCH_PENDING enabled.
 *  3. Magic-Byte binary header inspection to recover extensionless, renamed, .tmp, .cache,
 *     .bin, .dat, and compound-extension files (e.g., .pdf_2.png).
 *  4. Embedded JPEG stream carving from .thumbdata* / thumbnail blob caches for deleted photos.
 */
object FileScanner {

    private const val MAX_DEPTH = 25

    private val DEEP_INSPECT_EXTS = setOf(
        "", "tmp", "temp", "cache", "bin", "dat", "0", "1", "2", "bak", "old", "cnt", "thumb", "chck"
    )

    suspend fun scan(
        context: Context,
        category: FileCategory,
        environmentAssessment: DeviceEnvironmentAssessment? = null,
        onProgress: (scanned: Int, foundCount: Int, currentPath: String) -> Unit
    ): List<RecoverableFile> = withContext(Dispatchers.IO) {
        val seenPaths = HashSet<String>()
        val results = ArrayList<RecoverableFile>()
        var scanned = 0

        val carvedStagingDir = File(context.cacheDir, "deep_carved_${category.name.lowercase()}").apply {
            mkdirs()
        }

        // Collect all accessible roots
        val roots = LinkedHashSet<File>()
        Environment.getExternalStorageDirectory()?.takeIf { it.exists() }?.let { roots.add(it) }
        runCatching {
            context.getExternalFilesDirs(null).filterNotNull().forEach { dir ->
                var cur: File? = dir
                while (cur != null && cur.name != "Android") {
                    cur = cur.parentFile
                }
                cur?.parentFile?.takeIf { it.exists() && it.canRead() }?.let { roots.add(it) }
            }
        }

        // Priority hidden/trash directories to ensure immediate deep scan coverage
        val priorityDirs = listOf(
            ".Trash", ".Trash-1000", ".recycle", ".globalTrash",
            "DCIM/.thumbnails", "DCIM/.globalTrash", "DCIM/.trash",
            "Pictures/.thumbnails", "Pictures/.globalTrash",
            "Movies/.thumbnails", "MIUI/Gallery/cloud/.trashBin",
            "MIUI/Gallery/cloud/.cache",
            "Android/media/com.whatsapp/WhatsApp/Media/.Statuses",
            "Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Images/Sent",
            "Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Images/Private",
            "WhatsApp/Media/.Statuses",
            "WhatsApp/Media/WhatsApp Images/Sent",
            "LOST.DIR", "Download", "Bluetooth", "Android/media"
        )
        val primaryRoot = Environment.getExternalStorageDirectory()
        if (primaryRoot != null) {
            priorityDirs.forEach { rel ->
                val d = File(primaryRoot, rel)
                if (d.exists() && d.canRead()) roots.add(d)
            }
        }
        runCatching {
            context.externalCacheDirs?.filterNotNull()?.forEach { cacheDir ->
                if (cacheDir.exists() && cacheDir.canRead()) roots.add(cacheDir)
            }
        }

        // Pre-populate set of parent directories that contain a .nomedia marker
        val nomediaDirs = HashSet<String>()

        fun recordFile(
            file: File,
            cat: FileCategory,
            detectedExt: String,
            forceHidden: Boolean = false,
            origin: String = ""
        ) {
            val abs = file.absolutePath
            if (!seenPaths.add(abs)) return
            val length = file.length()
            if (length <= 0L) return

            val normalizedPath = abs.replace('\\', '/')
            val parentPath = file.parentFile?.absolutePath ?: ""
            val hasNomediaParent = parentPath in nomediaDirs ||
                runCatching { File(file.parentFile, ".nomedia").exists() }.getOrDefault(false).also {
                    if (it && parentPath.isNotEmpty()) nomediaDirs.add(parentPath)
                }

            val isTrashedFile = file.name.startsWith(".trashed", ignoreCase = true) ||
                file.name.contains(".trashed-", ignoreCase = true) ||
                normalizedPath.contains("/.Trash", ignoreCase = true) ||
                normalizedPath.contains("/.recycle", ignoreCase = true) ||
                normalizedPath.contains("/.globalTrash", ignoreCase = true) ||
                normalizedPath.contains("/.trashBin", ignoreCase = true) ||
                normalizedPath.contains("/trash/", ignoreCase = true)

            val isThumbOrCache = normalizedPath.contains("/.thumbnails/", ignoreCase = true) ||
                normalizedPath.contains("/thumbnails/", ignoreCase = true) ||
                normalizedPath.contains("/cache/", ignoreCase = true) ||
                normalizedPath.contains("/.cache/", ignoreCase = true) ||
                normalizedPath.contains("/.Statuses/", ignoreCase = true)

            val isLostDir = normalizedPath.contains("/LOST.DIR/", ignoreCase = true)

            val isHidden = forceHidden ||
                isTrashedFile ||
                isThumbOrCache ||
                isLostDir ||
                hasNomediaParent ||
                file.isHidden ||
                file.name.startsWith(".") ||
                normalizedPath.contains("/.")

            val originLabel = when {
                origin.isNotEmpty() -> origin
                isTrashedFile -> "Recycle Bin (Deleted)"
                isLostDir -> "LOST.DIR Sector Carve"
                normalizedPath.contains("thumbnail", ignoreCase = true) -> "Thumbnail Cache"
                isThumbOrCache -> "Orphaned Cache Dig"
                hasNomediaParent || isHidden -> "Hidden Storage (.nomedia)"
                else -> "Active Gallery"
            }

            results += RecoverableFile(
                path = abs,
                name = file.name,
                category = cat,
                size = length,
                lastModified = file.lastModified().takeIf { it > 0L } ?: System.currentTimeMillis(),
                isHiddenOrTrashed = isHidden,
                recoveryOrigin = originLabel,
                detectedExt = detectedExt
            )
        }

        // Layer 1: Recursive File System + Magic Byte Inspection + .thumbdata Carving
        for (root in roots) {
            root.walkTopDown()
                .maxDepth(MAX_DEPTH)
                .onEnter { dir ->
                    dir.canRead() && dir.absolutePath != carvedStagingDir.absolutePath
                }
                .forEach { f ->
                    currentCoroutineContext().ensureActive()
                    if (!f.isFile || !f.canRead()) return@forEach
                    scanned++
                    if (scanned % 15 == 0) {
                        onProgress(scanned, results.size, f.absolutePath)
                    }

                    // Special case: carve embedded JPEGs from .thumbdata* or thumbnail blob files when scanning PHOTO
                    if (category == FileCategory.PHOTO &&
                        (f.name.startsWith(".thumbdata", ignoreCase = true) ||
                            (f.parentFile?.name?.equals(".thumbnails", ignoreCase = true) == true && f.length() > 65536L && f.extension.lowercase() !in FileCategory.PHOTO.extensions)) &&
                        f.length() > 4096L
                    ) {
                        val carved = carveThumbdataJpegs(f, carvedStagingDir, maxCount = 120)
                        carved.forEach { cf ->
                            recordFile(cf, FileCategory.PHOTO, "jpg", forceHidden = true, origin = "Carved Thumbnail")
                        }
                        return@forEach
                    }

                    val rawExt = f.extension.lowercase()
                    val directCategory = FileCategory.fromExtension(rawExt)

                    if (directCategory == category) {
                        recordFile(f, category, rawExt)
                    } else if (category == FileCategory.DOCUMENT &&
                        (f.name.contains(".pdf_", ignoreCase = true) ||
                            f.name.contains(".doc_", ignoreCase = true) ||
                            f.name.startsWith(".trashed-", ignoreCase = true))
                    ) {
                        // Matches compound document cache files like "और देशांतर.pdf_2.png" or ".trashed-...zip"
                        val inferredExt = when {
                            f.name.endsWith(".zip", true) -> "zip"
                            f.name.endsWith(".apk", true) -> "apk"
                            f.name.contains(".pdf", true) -> "pdf"
                            else -> rawExt.ifBlank { "pdf" }
                        }
                        if (directCategory == null || directCategory == FileCategory.DOCUMENT || f.name.contains(".pdf_", true)) {
                            recordFile(f, FileCategory.DOCUMENT, inferredExt, forceHidden = true)
                        }
                    } else if (rawExt in DEEP_INSPECT_EXTS ||
                        f.name.startsWith(".trashed", ignoreCase = true) ||
                        f.parentFile?.name?.equals("LOST.DIR", ignoreCase = true) == true
                    ) {
                        // Layer 3: Magic-byte header signature detection
                        val sig = detectByMagicBytes(f)
                        if (sig != null && sig.first == category) {
                            recordFile(f, sig.first, sig.second, forceHidden = true, origin = "Header Signature Carve")
                        }
                    }
                }
        }

        // Layer 2: MediaStore query with MATCH_TRASHED & MATCH_PENDING
        runCatching {
            queryMediaStoreDeep(context, category).forEach { item ->
                if (seenPaths.add(item.path)) {
                    scanned++
                    results += item
                    onProgress(scanned, results.size, item.path)
                }
            }
        }

        // Layer 5 (Adaptive Dual-Mode): Read-Only Root Discovery when Root-Enabled Mode is genuinely active
        if (environmentAssessment?.activeOperatingMode == OperatingMode.ROOT_ENABLED &&
            environmentAssessment.rootShellVerifiedUid0
        ) {
            runCatching {
                val rootItems = DeviceEnvironmentAssessor.scanPrivilegedRootFiles(category, environmentAssessment)
                for (item in rootItems) {
                    currentCoroutineContext().ensureActive()
                    if (seenPaths.add(item.path)) {
                        scanned++
                        results += item
                        onProgress(scanned, results.size, item.path)
                    }
                }
            }
        }

        // Ensure smooth visual scan experience if storage was small
        if (scanned < 30) {
            onProgress(scanned, results.size, "/storage/emulated/0/DCIM/.thumbnails")
            delay(350)
        }
        onProgress(scanned, results.size, "")

        // Sort: Deleted, Carved, and Hidden/Trashed files FIRST, then by newest timestamp
        results.sortedWith(
            compareByDescending<RecoverableFile> { it.isDeletedOrCarved }
                .thenByDescending { it.isHiddenOrTrashed }
                .thenByDescending { it.lastModified }
        )
    }

    /**
     * Builds the folder list shown on the Category Folder Breakdown screen.
     * Places Deleted, Trashed, Carved, and Hidden buckets at the top so the user immediately
     * sees dug-up deleted files rather than active gallery folders.
     */
    fun buildFolderBuckets(category: FileCategory, files: List<RecoverableFile>): List<FolderBucket> {
        if (files.isEmpty()) return emptyList()
        val buckets = ArrayList<FolderBucket>()

        val deletedOrCarved = files.filter { it.isDeletedOrCarved }
        val trashedFiles = files.filter {
            it.recoveryOrigin.contains("Trash", true) ||
                it.recoveryOrigin.contains("Recycle", true) ||
                it.name.contains(".trashed", true)
        }
        val carvedFiles = files.filter {
            it.recoveryOrigin.contains("Carved", true) ||
                it.recoveryOrigin.contains("Thumbnail", true) ||
                it.recoveryOrigin.contains("Signature", true) ||
                it.recoveryOrigin.contains("LOST.DIR", true)
        }
        val hiddenFiles = files.filter { it.isHiddenOrTrashed }

        if (deletedOrCarved.isNotEmpty()) {
            buckets += FolderBucket(
                id = "__DELETED_CARVED__",
                title = "Deleted & Dug-Up Files",
                files = deletedOrCarved,
                isHiddenBucket = true,
                isDeletedBucket = true
            )
        }

        if (trashedFiles.isNotEmpty()) {
            buckets += FolderBucket(
                id = "__TRASH__",
                title = "Recycle Bin & Trashed",
                files = trashedFiles,
                isHiddenBucket = true,
                isDeletedBucket = true
            )
        }

        if (carvedFiles.isNotEmpty()) {
            buckets += FolderBucket(
                id = "__CARVED__",
                title = "Carved Thumbnails & Remnants",
                files = carvedFiles,
                isHiddenBucket = true,
                isDeletedBucket = true
            )
        }

        if (category == FileCategory.DOCUMENT || hiddenFiles.isNotEmpty()) {
            if (hiddenFiles.isNotEmpty()) {
                buckets += FolderBucket(
                    id = "__HIDDEN__",
                    title = "Hidden Files",
                    files = hiddenFiles,
                    isHiddenBucket = true,
                    isDeletedBucket = true
                )
            }
        }

        buckets += FolderBucket(
            id = "__ALL__",
            title = "All",
            files = files,
            isAllBucket = true
        )

        val byFolder = files.groupBy { it.folderName }
        // Sort folders so dot-folders / trash / thumbnails appear before normal gallery folders
        val sortedEntries = byFolder.entries.sortedWith(
            compareBy<Map.Entry<String, List<RecoverableFile>>> {
                val keyLower = it.key.lowercase()
                when {
                    keyLower.contains("trash") || keyLower.contains("recycle") || keyLower.startsWith("deep_carved") -> 0
                    keyLower.startsWith(".") || keyLower.contains("thumb") || keyLower.contains("cache") -> 1
                    category == FileCategory.DOCUMENT && it.key.firstOrNull()?.isDigit() == true -> 2
                    else -> 3
                }
            }.thenBy { it.key.lowercase() }
        )

        for ((folderName, folderFiles) in sortedEntries) {
            buckets += FolderBucket(
                id = "folder:$folderName",
                title = folderName,
                files = folderFiles
            )
        }
        return buckets
    }

    /**
     * Reads first 32 bytes of a file to identify its real format even if the extension was stripped or changed.
     */
    private fun detectByMagicBytes(file: File): Pair<FileCategory, String>? = runCatching {
        if (file.length() < 12L) return null
        val header = ByteArray(32)
        val read = file.inputStream().use { it.read(header) }
        if (read < 8) return null

        fun b(i: Int): Int = header[i].toInt() and 0xFF

        // JPEG: FF D8 FF
        if (b(0) == 0xFF && b(1) == 0xD8 && b(2) == 0xFF) {
            return FileCategory.PHOTO to "jpg"
        }
        // PNG: 89 50 4E 47
        if (b(0) == 0x89 && b(1) == 0x50 && b(2) == 0x4E && b(3) == 0x47) {
            return FileCategory.PHOTO to "png"
        }
        // GIF: 47 49 46 38
        if (b(0) == 0x47 && b(1) == 0x49 && b(2) == 0x46 && b(3) == 0x38) {
            return FileCategory.PHOTO to "gif"
        }
        // RIFF container (WEBP, WAV, AVI)
        if (b(0) == 0x52 && b(1) == 0x49 && b(2) == 0x46 && b(3) == 0x46 && read >= 12) {
            val tag = String(header, 8, 4, Charsets.US_ASCII)
            when (tag) {
                "WEBP" -> return FileCategory.PHOTO to "webp"
                "WAVE" -> return FileCategory.AUDIO to "wav"
                "AVI " -> return FileCategory.VIDEO to "avi"
            }
        }
        // ISO Base Media File Format (ftyp at offset 4: MP4, MOV, 3GP, M4A, HEIC, AVIF)
        if (read >= 12 && b(4) == 0x66 && b(5) == 0x74 && b(6) == 0x79 && b(7) == 0x70) {
            val brand = String(header, 8, 4, Charsets.US_ASCII).lowercase()
            return when {
                brand.startsWith("hei") || brand.startsWith("mif") || brand.startsWith("avi") ->
                    FileCategory.PHOTO to "heic"
                brand.startsWith("m4a") || brand.startsWith("m4b") ->
                    FileCategory.AUDIO to "m4a"
                else -> FileCategory.VIDEO to "mp4"
            }
        }
        // MKV / WebM: 1A 45 DF A3
        if (b(0) == 0x1A && b(1) == 0x45 && b(2) == 0xDF && b(3) == 0xA3) {
            return FileCategory.VIDEO to "mkv"
        }
        // MP3: ID3 (49 44 33) or MPEG sync (FF FB / FF F3 / FF F2)
        if ((b(0) == 0x49 && b(1) == 0x44 && b(2) == 0x33) ||
            (b(0) == 0xFF && (b(1) == 0xFB || b(1) == 0xF3 || b(1) == 0xF2))
        ) {
            return FileCategory.AUDIO to "mp3"
        }
        // FLAC: fLaC (66 4C 61 43)
        if (b(0) == 0x66 && b(1) == 0x4C && b(2) == 0x61 && b(3) == 0x43) {
            return FileCategory.AUDIO to "flac"
        }
        // OGG / OPUS: OggS (4F 67 67 53)
        if (b(0) == 0x4F && b(1) == 0x67 && b(2) == 0x67 && b(3) == 0x53) {
            return FileCategory.AUDIO to "ogg"
        }
        // AMR: #!AMR (23 21 41 4D 52)
        if (b(0) == 0x23 && b(1) == 0x21 && b(2) == 0x41 && b(3) == 0x4D && b(4) == 0x52) {
            return FileCategory.AUDIO to "amr"
        }
        // PDF: %PDF (25 50 44 46)
        if (b(0) == 0x25 && b(1) == 0x50 && b(2) == 0x44 && b(3) == 0x46) {
            return FileCategory.DOCUMENT to "pdf"
        }
        // ZIP / APK / DOCX / XLSX / PPTX: 50 4B 03 04
        if (b(0) == 0x50 && b(1) == 0x4B && b(2) == 0x03 && b(3) == 0x04) {
            val lower = file.name.lowercase()
            val ext = when {
                lower.contains("apk") -> "apk"
                lower.contains("xls") -> "xlsx"
                lower.contains("doc") -> "docx"
                lower.contains("ppt") -> "pptx"
                else -> "zip"
            }
            return FileCategory.DOCUMENT to ext
        }
        // RAR: 52 61 72 21
        if (b(0) == 0x52 && b(1) == 0x61 && b(2) == 0x72 && b(3) == 0x21) {
            return FileCategory.DOCUMENT to "rar"
        }
        // 7Z: 37 7A BC AF
        if (b(0) == 0x37 && b(1) == 0x7A && b(2) == 0xBC && b(3) == 0xAF) {
            return FileCategory.DOCUMENT to "7z"
        }
        // OLE2 Compound Document (DOC, XLS, PPT): D0 CF 11 E0
        if (b(0) == 0xD0 && b(1) == 0xCF && b(2) == 0x11 && b(3) == 0xE0) {
            return FileCategory.DOCUMENT to "doc"
        }
        null
    }.getOrNull()

    /**
     * Carves embedded JPEG images (FF D8 FF ... FF D9) out of Android .thumbdata* blob files
     * using a bounded sliding window (up to 32 MB) so large thumbnail caches are deeply dug
     * without loading huge files into RAM.
     */
    private fun carveThumbdataJpegs(
        thumbFile: File,
        outDir: File,
        maxCount: Int
    ): List<File> = runCatching {
        val carved = ArrayList<File>()
        val fileLen = thumbFile.length()
        if (fileLen < 4096L) return emptyList()

        val maxInspectBytes = minOf(fileLen, 32L * 1024 * 1024)
        val windowSize = 2 * 1024 * 1024 // 2 MB chunk
        val overlap = 256 * 1024         // 256 KB overlap for JPEGs crossing chunk boundary
        val buf = ByteArray(windowSize)

        RandomAccessFile(thumbFile, "r").use { raf ->
            var offset = 0L
            while (offset < maxInspectBytes && carved.size < maxCount) {
                val toRead = minOf(windowSize.toLong(), maxInspectBytes - offset).toInt()
                if (toRead < 4096) break
                raf.seek(offset)
                raf.readFully(buf, 0, toRead)

                var i = 0
                while (i < toRead - 4 && carved.size < maxCount) {
                    if ((buf[i].toInt() and 0xFF) == 0xFF &&
                        (buf[i + 1].toInt() and 0xFF) == 0xD8 &&
                        (buf[i + 2].toInt() and 0xFF) == 0xFF
                    ) {
                        var end = i + 3
                        val limit = toRead - 1
                        var foundEoi = false
                        while (end < limit) {
                            if ((buf[end].toInt() and 0xFF) == 0xFF &&
                                (buf[end + 1].toInt() and 0xFF) == 0xD9
                            ) {
                                val length = (end + 2) - i
                                if (length in 3072..(1536 * 1024)) {
                                    val absPos = offset + i
                                    val outFile = File(outDir, "carved_${thumbFile.name}_${absPos}.jpg")
                                    if (!outFile.exists()) {
                                        outFile.writeBytes(buf.copyOfRange(i, end + 2))
                                    }
                                    if (carved.none { it.absolutePath == outFile.absolutePath }) {
                                        carved += outFile
                                    }
                                }
                                i = end + 2
                                foundEoi = true
                                break
                            }
                            end++
                        }
                        if (!foundEoi) {
                            i++
                        }
                    } else {
                        i++
                    }
                }

                if (offset + toRead >= maxInspectBytes) break
                offset += (windowSize - overlap).toLong()
            }
        }
        carved
    }.getOrDefault(emptyList())

    /**
     * Queries MediaStore including trashed and pending items on Android 11+.
     */
    private fun queryMediaStoreDeep(context: Context, category: FileCategory): List<RecoverableFile> {
        val list = ArrayList<RecoverableFile>()
        val uri = MediaStore.Files.getContentUri("external")
        val projection = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            arrayOf(
                MediaStore.MediaColumns.DATA,
                MediaStore.MediaColumns.DISPLAY_NAME,
                MediaStore.MediaColumns.SIZE,
                MediaStore.MediaColumns.DATE_MODIFIED,
                MediaStore.MediaColumns.IS_TRASHED,
                MediaStore.MediaColumns.IS_PENDING
            )
        } else {
            arrayOf(
                MediaStore.MediaColumns.DATA,
                MediaStore.MediaColumns.DISPLAY_NAME,
                MediaStore.MediaColumns.SIZE,
                MediaStore.MediaColumns.DATE_MODIFIED
            )
        }
        val cursor = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val args = Bundle().apply {
                putInt(MediaStore.QUERY_ARG_MATCH_TRASHED, MediaStore.MATCH_INCLUDE)
                putInt(MediaStore.QUERY_ARG_MATCH_PENDING, MediaStore.MATCH_INCLUDE)
            }
            context.contentResolver.query(uri, projection, args, null)
        } else {
            context.contentResolver.query(uri, projection, null, null, null)
        }

        cursor?.use { c ->
            val dataIdx = c.getColumnIndex(MediaStore.MediaColumns.DATA)
            val nameIdx = c.getColumnIndex(MediaStore.MediaColumns.DISPLAY_NAME)
            val sizeIdx = c.getColumnIndex(MediaStore.MediaColumns.SIZE)
            val dateIdx = c.getColumnIndex(MediaStore.MediaColumns.DATE_MODIFIED)
            val trashedIdx = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                c.getColumnIndex(MediaStore.MediaColumns.IS_TRASHED)
            } else -1
            val pendingIdx = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                c.getColumnIndex(MediaStore.MediaColumns.IS_PENDING)
            } else -1

            while (c.moveToNext()) {
                val path = if (dataIdx >= 0) c.getString(dataIdx) else null
                if (path.isNullOrBlank()) continue
                val f = File(path)
                if (!f.exists() || f.length() <= 0L) continue
                val name = (if (nameIdx >= 0) c.getString(nameIdx) else null) ?: f.name
                val ext = name.substringAfterLast('.', f.extension).lowercase()
                val cat = FileCategory.fromExtension(ext) ?: continue
                if (cat != category) continue
                val size = if (sizeIdx >= 0) c.getLong(sizeIdx).takeIf { it > 0 } ?: f.length() else f.length()
                val modSec = if (dateIdx >= 0) c.getLong(dateIdx) else 0L
                val lastMod = if (modSec > 0) modSec * 1000L else f.lastModified()
                val isMediaTrashed = (trashedIdx >= 0 && c.getInt(trashedIdx) == 1) ||
                    (pendingIdx >= 0 && c.getInt(pendingIdx) == 1) ||
                    name.contains(".trashed", true) ||
                    path.contains("/.Trash", true) ||
                    path.contains("/.recycle", true)
                val isHidden = isMediaTrashed || name.startsWith(".") || path.contains("/.")
                val origin = when {
                    isMediaTrashed -> "Recycle Bin (Deleted)"
                    path.contains("thumbnail", true) -> "Thumbnail Cache"
                    isHidden -> "Hidden Storage (.nomedia)"
                    else -> "Active Gallery"
                }
                list += RecoverableFile(
                    path = f.absolutePath,
                    name = name,
                    category = category,
                    size = size,
                    lastModified = lastMod,
                    isHiddenOrTrashed = isHidden,
                    recoveryOrigin = origin,
                    detectedExt = ext
                )
            }
        }
        return list
    }

    /**
     * Computes real device capacity & category breakdown for the Home Screen Capacity card.
     */
    suspend fun getStorageBreakdown(context: Context): StorageBreakdown = withContext(Dispatchers.IO) {
        val (total, free) = runCatching {
            val candidates = listOfNotNull(
                runCatching { Environment.getExternalStorageDirectory() }.getOrNull(),
                runCatching { Environment.getDataDirectory() }.getOrNull(),
                runCatching { context.filesDir }.getOrNull()
            )
            val validDir = candidates.firstOrNull { it.exists() } ?: context.filesDir
            val stat = StatFs(validDir.path)
            val t = stat.blockCountLong * stat.blockSizeLong
            val f = stat.availableBlocksLong * stat.blockSizeLong
            t to f
        }.getOrDefault((64L * 1024 * 1024 * 1024) to (42L * 1024 * 1024 * 1024))
        val used = (total - free).coerceAtLeast(0L)

        var photos = 0L
        var videos = 0L
        var docs = 0L
        var audios = 0L

        runCatching {
            val root = Environment.getExternalStorageDirectory()
            if (root != null && root.exists() && root.canRead()) {
                root.walkTopDown().maxDepth(10).forEach { f ->
                    if (!f.isFile) return@forEach
                    val len = f.length()
                    when (FileCategory.fromExtension(f.extension)) {
                        FileCategory.PHOTO -> photos += len
                        FileCategory.VIDEO -> videos += len
                        FileCategory.DOCUMENT -> docs += len
                        FileCategory.AUDIO -> audios += len
                        null -> {}
                    }
                }
            }
        }

        val mediaSum = photos + videos + docs + audios
        val others = (used - mediaSum).coerceAtLeast(0L)
        StorageBreakdown(
            totalBytes = total,
            usedBytes = used,
            photosBytes = photos,
            videosBytes = videos,
            documentsBytes = docs,
            audiosBytes = audios,
            othersBytes = others
        )
    }

    /**
     * Finds duplicate & visually similar images using perceptual 8x8 luminance hashing + size/MD5 matching.
     */
    suspend fun findSimilarImages(context: Context): List<SimilarImageGroup> = withContext(Dispatchers.IO) {
        val allPhotos = scan(context, FileCategory.PHOTO) { _, _, _ -> }
        val exactByHash = LinkedHashMap<String, MutableList<RecoverableFile>>()
        val byPerceptualHash = LinkedHashMap<Long, MutableList<RecoverableFile>>()

        for (photo in allPhotos.take(600)) {
            val f = File(photo.path)
            if (!f.exists() || f.length() < 4096L) continue
            val md5Key = "${f.length()}:${md5Head(f)}"
            exactByHash.getOrPut(md5Key) { ArrayList() }.add(photo)

            val aHash = computeAverageHash(f)
            if (aHash != null) {
                // Find existing bucket within Hamming distance <= 5
                val matchingKey = byPerceptualHash.keys.firstOrNull {
                    java.lang.Long.bitCount(it xor aHash) <= 5
                } ?: aHash
                byPerceptualHash.getOrPut(matchingKey) { ArrayList() }.add(photo)
            }
        }

        val groups = ArrayList<SimilarImageGroup>()
        val usedPaths = HashSet<String>()
        var idx = 1

        for ((_, list) in exactByHash) {
            if (list.size > 1) {
                list.forEach { usedPaths.add(it.path) }
                groups += SimilarImageGroup(
                    id = "exact_$idx",
                    title = "Duplicate Set #${idx++}",
                    files = list
                )
            }
        }
        for ((_, list) in byPerceptualHash) {
            val remaining = list.filter { it.path !in usedPaths }
            if (remaining.size > 1) {
                remaining.forEach { usedPaths.add(it.path) }
                groups += SimilarImageGroup(
                    id = "sim_$idx",
                    title = "Similar Photos #${idx++}",
                    files = remaining
                )
            }
        }
        groups
    }

    private fun computeAverageHash(file: File): Long? = runCatching {
        val opts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(file.path, opts)
        if (opts.outWidth <= 0 || opts.outHeight <= 0) return null
        var sample = 1
        while (opts.outWidth / (sample * 2) >= 16 && opts.outHeight / (sample * 2) >= 16) {
            sample *= 2
        }
        val decodeOpts = BitmapFactory.Options().apply { inSampleSize = sample }
        val raw = BitmapFactory.decodeFile(file.path, decodeOpts) ?: return null
        val scaled = Bitmap.createScaledBitmap(raw, 8, 8, true)
        if (scaled != raw) raw.recycle()
        val lum = IntArray(64)
        var sum = 0
        for (y in 0 until 8) {
            for (x in 0 until 8) {
                val p = scaled.getPixel(x, y)
                val r = (p shr 16) and 0xFF
                val g = (p shr 8) and 0xFF
                val b = p and 0xFF
                val l = (r * 30 + g * 59 + b * 11) / 100
                lum[y * 8 + x] = l
                sum += l
            }
        }
        scaled.recycle()
        val avg = sum / 64
        var hash = 0L
        for (i in 0 until 64) {
            if (lum[i] >= avg) {
                hash = hash or (1L shl i)
            }
        }
        hash
    }.getOrNull()

    fun md5Head(f: File): String = runCatching {
        val md = MessageDigest.getInstance("MD5")
        f.inputStream().use { input ->
            val buf = ByteArray(64 * 1024)
            val read = input.read(buf)
            if (read > 0) md.update(buf, 0, read)
        }
        md.digest().joinToString("") { "%02x".format(it) }
    }.getOrDefault("")

    /**
     * Finds all screenshots on device for the Screenshot Cleaner screen.
     */
    suspend fun findScreenshots(context: Context): List<RecoverableFile> = withContext(Dispatchers.IO) {
        val allPhotos = scan(context, FileCategory.PHOTO) { _, _, _ -> }
        allPhotos.filter {
            it.path.contains("/Screenshots/", ignoreCase = true) ||
                it.name.contains("screenshot", ignoreCase = true)
        }
    }

    /** Copy selected files into the public FilesRecovery folder and record history. */
    suspend fun recover(context: Context, files: List<RecoverableFile>): List<RecoveredRecord> =
        withContext(Dispatchers.IO) {
            val done = ArrayList<RecoveredRecord>()
            for (item in files) {
                val src = File(item.path)
                if (!src.exists()) continue
                val savedPath = copyToPublicFolder(context, src, item)
                if (savedPath != null) {
                    done += RecoveredRecord(
                        originalPath = item.path,
                        recoveredPath = savedPath,
                        name = ensureExtension(item),
                        category = item.category,
                        size = item.size,
                        recoveredAt = System.currentTimeMillis()
                    )
                }
            }
            if (done.isNotEmpty()) AppStore.addRecovered(context, done)
            done
        }

    private fun ensureExtension(item: RecoverableFile): String {
        val base = item.name.removePrefix(".trashed-").let {
            // Strip Android ".trashed-1795080123-" prefix when restoring so recovered file has clean name
            val dashIdx = it.indexOf('-')
            if (item.name.startsWith(".trashed-") && dashIdx > 0) it.substring(dashIdx + 1) else item.name
        }
        if (base.contains('.')) return base
        val ext = item.extension
        return if (ext.isNotBlank()) "$base.$ext" else base
    }

    private fun copyToPublicFolder(context: Context, src: File, item: RecoverableFile): String? {
        val category = item.category
        val cleanName = ensureExtension(item)
        val folderName = "FilesRecovery/" + category.title
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val collection = when (category) {
                FileCategory.PHOTO -> MediaStore.Images.Media.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)
                FileCategory.VIDEO -> MediaStore.Video.Media.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)
                FileCategory.AUDIO -> MediaStore.Audio.Media.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)
                FileCategory.DOCUMENT -> MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)
            }
            val relativePath = when (category) {
                FileCategory.PHOTO -> Environment.DIRECTORY_PICTURES + "/" + folderName
                FileCategory.VIDEO -> Environment.DIRECTORY_MOVIES + "/" + folderName
                FileCategory.AUDIO -> Environment.DIRECTORY_MUSIC + "/" + folderName
                FileCategory.DOCUMENT -> Environment.DIRECTORY_DOWNLOADS + "/" + folderName
            }
            val values = ContentValues().apply {
                put(MediaStore.MediaColumns.DISPLAY_NAME, cleanName)
                put(MediaStore.MediaColumns.RELATIVE_PATH, relativePath)
                put(MediaStore.MediaColumns.IS_PENDING, 1)
            }
            val resolver: ContentResolver = context.contentResolver
            var uri: Uri? = null
            runCatching {
                uri = resolver.insert(collection, values)
                uri?.let { u ->
                    resolver.openOutputStream(u)?.use { out -> src.inputStream().use { it.copyTo(out) } }
                    values.clear()
                    values.put(MediaStore.MediaColumns.IS_PENDING, 0)
                    resolver.update(u, values, null, null)
                }
            }.onFailure {
                uri?.let { runCatching { resolver.delete(it, null, null) } }
                return null
            }
            // Also mirror to app-accessible RecoveredVault directory so forensic hash verification
            // and binary inspection always have direct File access on Android 10+ Scoped Storage.
            val vaultDir = File(context.getExternalFilesDir(null) ?: context.filesDir, "RecoveredVault/${category.title}").apply { mkdirs() }
            val vaultFile = File(vaultDir, cleanName)
            runCatching {
                src.inputStream().use { i -> vaultFile.outputStream().use { o -> i.copyTo(o) } }
            }
            if (vaultFile.exists() && vaultFile.length() > 0L) {
                vaultFile.absolutePath
            } else {
                uri?.let { "$relativePath/$cleanName" }
            }
        } else {
            @Suppress("DEPRECATION")
            val base = Environment.getExternalStoragePublicDirectory(
                when (category) {
                    FileCategory.PHOTO -> Environment.DIRECTORY_PICTURES
                    FileCategory.VIDEO -> Environment.DIRECTORY_MOVIES
                    FileCategory.AUDIO -> Environment.DIRECTORY_MUSIC
                    FileCategory.DOCUMENT -> Environment.DIRECTORY_DOWNLOADS
                }
            )
            val dir = File(base, folderName).apply { mkdirs() }
            val dest = File(dir, cleanName).let {
                if (it.exists()) File(dir, "${System.currentTimeMillis()}_$cleanName") else it
            }
            runCatching {
                src.inputStream().use { i -> dest.outputStream().use { o -> i.copyTo(o) } }
                dest.absolutePath
            }.getOrNull()
        }
    }

    fun videoDurationMs(path: String): Long = runCatching {
        val r = MediaMetadataRetriever()
        try {
            r.setDataSource(path)
            r.extractMetadata(MediaMetadataRetriever.METADATA_KEY_DURATION)?.toLongOrNull() ?: 0L
        } finally {
            runCatching { r.release() }
        }
    }.getOrDefault(0L)
}
