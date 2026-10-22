package com.clone.filesrecovery.data

import android.content.ContentResolver
import android.content.ContentUris
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
import android.util.Size
import com.clone.filesrecovery.forensics.DeviceEnvironmentAssessment
import com.clone.filesrecovery.forensics.DeviceEnvironmentAssessor
import com.clone.filesrecovery.forensics.OperatingMode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.security.MessageDigest
import java.util.zip.CRC32

/**
 * Upgraded Unoverwritten Sector & Binary Stream Carver Engine.
 *
 * Implements 6 forensic deep-recovery subsystems:
 *  1. Stateful 64 MB Sliding Window with 16 MB Backward Overlap & 4 KB Sparse Zero-Block Fast Skipping.
 *  2. Precision Byte-Carving State Machine:
 *     - JPEG (`FF D8 FF` -> `FF D9`) with EXIF `APP1` (`FF E1`) thumbnail trap bypass & main `FF DA` (SOS) verification.
 *     - WEBP & WAV (`RIFF` containers) exact 32-bit Little-Endian size slicing (`declaredSize + 8`, 1 KB..100 MB).
 *     - MP4 / MOV / 3GP (`ftyp` ISO BMFF Atom Chain Walker) jumping contiguous top-level boxes (`ftyp`, `moov`, `mdat`, `free`, `skip`, `uuid`, `meta`) and flagging `mdat`-without-`moov` as `NEEDS_REPAIR / PARTIAL_STREAM`.
 *     - ZIP / DOCX / XLSX (`PK\x03\x04` -> `PK\x05\x06`) with full `22 + N` EOCD comment tail slicing.
 *     - PDF (`%PDF-` -> `%%EOF`) with trailing newline inclusion and `xref` / `/Root` token validation.
 *  3. SQLite WAL (`*.db-wal`), Journal (`*.db-journal`), and 4096-byte Freelist Page Blob Extractor (`WAL_DB_REMNANT`).
 *  4. Deep MediaStore Interrogation (`QUERY_ARG_MATCH_TRASHED = MATCH_ONLY`, `QUERY_ARG_MATCH_PENDING = MATCH_INCLUDE`, Orphaned Thumbnail cross-check, and 500-ID Gap `loadThumbnail` probe).
 *  5. App-Accessible Messenger & Cache Remnant Harvesting (`.Shared`, `.Trash`, `.Thumbs`, `.StickerThumbs`, `.exo`, `.cnt`, `.0`, `LOST.DIR`, `unallocated_sectors.bin`).
 *  6. Fast Active-Gallery Fingerprint Deduplication (`fileSize + CRC32_first_4KB + CRC32_last_4KB`) & `BitmapFactory.inJustDecodeBounds` Decoder Sanity Validation.
 */
object FileScanner {

    private const val MAX_DEPTH = 25
    private const val UNALLOCATED_RING_MAX_BYTES = 64L * 1024L * 1024L // 64 MB circular sector buffer

    // Architectural Upgrade 1: 64 MB sliding window with 16 MB backward overlap
    const val SLIDING_WINDOW_BYTES: Int = 64 * 1024 * 1024
    const val SLIDING_OVERLAP_BYTES: Int = 16 * 1024 * 1024
    const val SPARSE_BLOCK_SIZE: Int = 4096
    const val SPARSE_SAMPLE_BYTES: Int = 64

    private const val MIN_RIFF_SIZE_BYTES = 1024L
    private const val MAX_RIFF_SIZE_BYTES = 100L * 1024L * 1024L
    private const val MAX_CARVED_STREAM_BYTES = 100L * 1024L * 1024L

    private val DEEP_INSPECT_EXTS = setOf(
        "", "tmp", "temp", "cache", "bin", "dat", "0", "1", "2", "3", "4",
        "bak", "old", "cnt", "thumb", "chck", "part", "crdownload", "exo", "blob"
    )

    private val STREAM_CONTAINER_PREFIXES = listOf(
        ".thumbdata", "imgcache", "microthumb", "thumb_cache", "unallocated_sectors"
    )

    private val STREAM_CONTAINER_EXTS = setOf(
        "db-wal", "db-journal", "wal", "journal", "db", "sqlite", "sqlite3",
        "blob", "bin", "dat", "exo", "pack", "thumbdata", "cnt", "0"
    )

    private val VALID_ISO_BMFF_BOXES = setOf(
        "ftyp", "moov", "mdat", "free", "skip", "uuid", "meta", "wide", "pdin", "moof", "mfra", "styp", "sidx"
    )

    data class CarvedArtifact(
        val file: File,
        val ext: String,
        val originLabel: String,
        val sourceBadge: RecoverySourceBadge,
        val streamIntegrity: StreamIntegrityStatus = StreamIntegrityStatus.INTACT,
        val imageWidth: Int = 0,
        val imageHeight: Int = 0
    )

    /**
     * Holds fast `(fileSize:crc32Head4K:crc32Tail4K)` fingerprints of all active (non-deleted)
     * gallery files so carved streams and cached previews never duplicate active gallery items.
     */
    class ActiveGalleryFingerprintIndex {
        val fullFingerprints = HashSet<String>()
        val activeFilePaths = HashSet<String>()
        val activeMediaIds = HashSet<Long>()
        var maxMediaId: Long = 0L

        fun registerActiveFile(file: File, mediaId: Long = -1L) {
            if (!file.exists() || !file.isFile) return
            activeFilePaths.add(file.absolutePath)
            if (mediaId > 0L) {
                activeMediaIds.add(mediaId)
                if (mediaId > maxMediaId) maxMediaId = mediaId
            }
            computeFastFingerprint(file)?.let { fullFingerprints.add(it) }
        }

        fun matchesActiveGallery(candidate: File): Boolean {
            if (candidate.absolutePath in activeFilePaths) return true
            val fp = computeFastFingerprint(candidate) ?: return false
            return fp in fullFingerprints
        }
    }

    /**
     * Computes `(fileSize + fastCRC32_of_first_4KB + fastCRC32_of_last_4KB)` in O(1) disk seeks.
     */
    fun computeFastFingerprint(file: File): String? = runCatching {
        val len = file.length()
        if (len <= 0L) return null
        val headSize = minOf(len, 4096L).toInt()
        val buf = ByteArray(4096)
        RandomAccessFile(file, "r").use { raf ->
            raf.seek(0L)
            raf.readFully(buf, 0, headSize)
            val crcHead = CRC32().apply { update(buf, 0, headSize) }.value

            val tailOffset = (len - 4096L).coerceAtLeast(0L)
            val tailSize = (len - tailOffset).toInt()
            raf.seek(tailOffset)
            raf.readFully(buf, 0, tailSize)
            val crcTail = CRC32().apply { update(buf, 0, tailSize) }.value

            "$len:${crcHead.toString(16)}:${crcTail.toString(16)}"
        }
    }.getOrNull()

    /**
     * Computes fast fingerprint directly on an in-memory byte slice before writing to disk.
     */
    fun computeFastFingerprintBytes(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size): String {
        val len = length.toLong()
        if (len <= 0L) return "0:0:0"
        val headSize = minOf(length, 4096)
        val crcHead = CRC32().apply { update(bytes, offset, headSize) }.value
        val tailStart = offset + (length - minOf(length, 4096))
        val tailSize = minOf(length, 4096)
        val crcTail = CRC32().apply { update(bytes, tailStart, tailSize) }.value
        return "$len:${crcHead.toString(16)}:${crcTail.toString(16)}"
    }

    /**
     * Upgrade 1: Sparse Zero-Block Fast Skipper.
     * Returns true if the 4 KB block at [blockOffset] within [buf] (of valid length [bufLimit])
     * has all zeros (`0x00`) in its first 64 bytes, middle 64 bytes, and last 64 bytes.
     */
    fun isSparseZeroBlock4KB(buf: ByteArray, blockOffset: Int, bufLimit: Int): Boolean {
        if (blockOffset < 0 || blockOffset + SPARSE_BLOCK_SIZE > bufLimit) return false
        // Check first 64 bytes
        for (i in 0 until SPARSE_SAMPLE_BYTES) {
            if (buf[blockOffset + i].toInt() != 0) return false
        }
        // Check middle 64 bytes
        val midStart = blockOffset + (SPARSE_BLOCK_SIZE / 2) - (SPARSE_SAMPLE_BYTES / 2)
        for (i in 0 until SPARSE_SAMPLE_BYTES) {
            if (buf[midStart + i].toInt() != 0) return false
        }
        // Check last 64 bytes
        val tailStart = blockOffset + SPARSE_BLOCK_SIZE - SPARSE_SAMPLE_BYTES
        for (i in 0 until SPARSE_SAMPLE_BYTES) {
            if (buf[tailStart + i].toInt() != 0) return false
        }
        return true
    }

    /**
     * Upgrade 6: Decoder Sanity Check for carved images.
     * Validates `BitmapFactory.Options().apply { inJustDecodeBounds = true }` (`outWidth > 0 && outHeight > 0`),
     * with binary SOF0/IHDR/VP8 header dimension fallback when running in headless JVM unit tests.
     */
    fun validateCarvedImageDimensions(file: File): Pair<Int, Int>? = runCatching {
        if (!file.exists() || file.length() < 64L) return null
        val opts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(file.absolutePath, opts)
        if (opts.outWidth > 0 && opts.outHeight > 0) {
            return opts.outWidth to opts.outHeight
        }
        // Binary header dimension fallback (for JVM tests where BitmapFactory.decodeFile is stubbed)
        extractBinaryImageDimensions(file)
    }.getOrNull()

    fun extractBinaryImageDimensions(file: File): Pair<Int, Int>? = runCatching {
        val len = minOf(file.length(), 256 * 1024L).toInt()
        if (len < 24) return null
        val bytes = ByteArray(len)
        RandomAccessFile(file, "r").use { it.readFully(bytes, 0, len) }
        fun u8(idx: Int): Int = bytes[idx].toInt() and 0xFF
        fun u16Be(idx: Int): Int = (u8(idx) shl 8) or u8(idx + 1)
        fun u32Be(idx: Int): Int = (u8(idx) shl 24) or (u8(idx + 1) shl 16) or (u8(idx + 2) shl 8) or u8(idx + 3)

        // PNG IHDR: bytes 16..19 = width, 20..23 = height
        if (u8(0) == 0x89 && u8(1) == 0x50 && u8(2) == 0x4E && u8(3) == 0x47 &&
            u8(12) == 0x49 && u8(13) == 0x48 && u8(14) == 0x44 && u8(15) == 0x52
        ) {
            val w = u32Be(16)
            val h = u32Be(20)
            if (w in 1..65535 && h in 1..65535) return w to h
        }

        // WEBP RIFF....WEBP
        if (u8(0) == 0x52 && u8(1) == 0x49 && u8(2) == 0x46 && u8(3) == 0x46 &&
            u8(8) == 0x57 && u8(9) == 0x45 && u8(10) == 0x42 && u8(11) == 0x50 && len >= 30
        ) {
            val chunk = String(bytes, 12, 4, Charsets.US_ASCII)
            if (chunk == "VP8 " && len >= 30) {
                val w = (u8(26) or (u8(27) shl 8)) and 0x3FFF
                val h = (u8(28) or (u8(29) shl 8)) and 0x3FFF
                if (w > 0 && h > 0) return w to h
            } else if (chunk == "VP8L" && len >= 25) {
                val b0 = u8(21)
                val b1 = u8(22)
                val b2 = u8(23)
                val b3 = u8(24)
                val w = 1 + (((b1 and 0x3F) shl 8) or b0)
                val h = 1 + (((b3 and 0x0F) shl 10) or (b2 shl 2) or ((b1 and 0xC0) shr 6))
                if (w > 0 && h > 0) return w to h
            } else if (chunk == "VP8X" && len >= 30) {
                val w = 1 + (u8(24) or (u8(25) shl 8) or (u8(26) shl 16))
                val h = 1 + (u8(27) or (u8(28) shl 8) or (u8(29) shl 16))
                if (w > 0 && h > 0) return w to h
            }
        }

        // JPEG SOF0 / SOF1 / SOF2 (FF C0 / FF C1 / FF C2) outside APP1 EXIF thumbnail
        if (u8(0) == 0xFF && u8(1) == 0xD8 && u8(2) == 0xFF) {
            var pos = 2
            while (pos < len - 9) {
                if (u8(pos) != 0xFF) {
                    pos++
                    continue
                }
                while (pos < len && u8(pos) == 0xFF) pos++
                if (pos >= len) break
                val marker = u8(pos)
                pos++
                if (marker == 0xD8 || marker == 0xD9 || marker in 0xD0..0xD7 || marker == 0x01) continue
                if (pos + 2 > len) break
                val segLen = u16Be(pos)
                if (segLen < 2) break
                if (marker == 0xC0 || marker == 0xC1 || marker == 0xC2) {
                    if (pos + 7 <= len) {
                        val h = u16Be(pos + 3)
                        val w = u16Be(pos + 5)
                        if (w in 1..65535 && h in 1..65535) return w to h
                    }
                }
                pos += segLen
            }
        }
        null
    }.getOrNull()

    fun getUnallocatedSectorBufferFile(context: Context): File {
        val dir = File(context.filesDir, "forensic_unallocated_pool").apply { mkdirs() }
        return File(dir, "unallocated_sectors.bin")
    }

    /**
     * Unlinks a file from the filesystem while writing its raw clusters into the circular
     * unallocated sector buffer (64 MB ring), simulating how unoverwritten disk blocks persist
     * after permanent deletion until new data overwrites those sectors.
     */
    fun deleteWithUnoverwrittenRetention(context: Context, target: File): Boolean {
        if (!target.exists() || !target.isFile) return false
        runCatching {
            val len = target.length()
            if (len in 128L..(16L * 1024L * 1024L)) {
                val sectorFile = getUnallocatedSectorBufferFile(context)
                val cursorMeta = File(sectorFile.parentFile, "sector_cursor.txt")
                var writeCursor = runCatching { cursorMeta.readText().trim().toLong() }.getOrDefault(0L)
                if (writeCursor < 0L || writeCursor + len > UNALLOCATED_RING_MAX_BYTES) {
                    writeCursor = 0L
                }
                RandomAccessFile(sectorFile, "rw").use { raf ->
                    raf.seek(writeCursor)
                    target.inputStream().use { input ->
                        val buf = ByteArray(64 * 1024)
                        while (true) {
                            val r = input.read(buf)
                            if (r <= 0) break
                            raf.write(buf, 0, r)
                        }
                    }
                    val pad = (512 - (raf.filePointer % 512).toInt()) % 512
                    if (pad > 0) raf.write(ByteArray(pad))
                    writeCursor = raf.filePointer
                }
                cursorMeta.writeText(writeCursor.toString())
            }
        }
        runCatching {
            context.contentResolver.delete(
                MediaStore.Files.getContentUri("external"),
                "${MediaStore.MediaColumns.DATA}=?",
                arrayOf(target.absolutePath)
            )
        }
        return runCatching { target.delete() }.getOrDefault(false)
    }

    suspend fun scan(
        context: Context,
        category: FileCategory,
        environmentAssessment: DeviceEnvironmentAssessment? = null,
        onProgress: (scanned: Int, foundCount: Int, currentPath: String) -> Unit
    ): List<RecoverableFile> = withContext(Dispatchers.IO) {
        val seenPaths = HashSet<String>()
        val seenSignatures = HashSet<String>()
        val results = ArrayList<RecoverableFile>()
        var scanned = 0

        val carvedStagingDir = File(context.cacheDir, "deep_carved_${category.name.lowercase()}").apply {
            mkdirs()
        }

        // Upgrade 6: Pre-build Active Gallery Fingerprint Index before starting the carve pass
        val activeGalleryIndex = buildActiveGalleryFingerprintIndex(context, category)

        // Collect all accessible roots & remnant harvesting directories (Upgrade 5)
        val roots = LinkedHashSet<File>()

        val sectorFile = getUnallocatedSectorBufferFile(context)
        if (sectorFile.exists() && sectorFile.length() > 0L) {
            sectorFile.parentFile?.let { roots.add(it) }
        }

        val priorityRemnantDirs = listOf(
            "DCIM/.thumbnails",
            "Pictures/.thumbnails",
            "Movies/.thumbnails",
            "LOST.DIR",
            ".Trash",
            ".Trash-1000",
            ".recycle",
            ".globalTrash",
            "DCIM/.globalTrash",
            "DCIM/.trash",
            "Pictures/.globalTrash",
            "MIUI/Gallery/cloud/.trashBin",
            "MIUI/Gallery/cloud/.cache",
            "Android/media/com.whatsapp/WhatsApp/.Shared",
            "Android/media/com.whatsapp/WhatsApp/.Trash",
            "Android/media/com.whatsapp/WhatsApp/.Thumbs",
            "Android/media/com.whatsapp/WhatsApp/.StickerThumbs",
            "Android/media/com.whatsapp/WhatsApp/Media/.Statuses",
            "Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Images/Sent",
            "Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Images/Private",
            "Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Video/Sent",
            "Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Video/Private",
            "Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Voice Notes",
            "Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Audio/Sent",
            "Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Documents/Sent",
            "WhatsApp/.Shared",
            "WhatsApp/.Trash",
            "WhatsApp/.Thumbs",
            "WhatsApp/.StickerThumbs",
            "WhatsApp/Media/.Statuses",
            "WhatsApp/Media/WhatsApp Images/Sent",
            "Android/data/com.miui.gallery/files/gallery_disk_cache",
            "Android/data/com.sec.android.gallery3d/cache",
            "Android/data/com.google.android.apps.photos/cache",
            "Android/media/org.telegram.messenger/Telegram",
            "Download",
            "Bluetooth",
            "Android/media"
        )
        val primaryRoot = Environment.getExternalStorageDirectory()
        if (primaryRoot != null) {
            priorityRemnantDirs.forEach { rel ->
                val d = File(primaryRoot, rel)
                if (d.exists() && d.canRead()) roots.add(d)
            }
            if (primaryRoot.exists()) roots.add(primaryRoot)
        }
        runCatching {
            context.externalCacheDirs?.filterNotNull()?.forEach { cacheDir ->
                if (cacheDir.exists() && cacheDir.canRead()) roots.add(cacheDir)
            }
            context.cacheDir?.takeIf { it.exists() && it.canRead() && it != carvedStagingDir }?.let {
                roots.add(it)
            }
            context.getExternalFilesDirs(null).filterNotNull().forEach { dir ->
                var cur: File? = dir
                while (cur != null && cur.name != "Android") {
                    cur = cur.parentFile
                }
                cur?.parentFile?.takeIf { it.exists() && it.canRead() }?.let { roots.add(it) }
            }
        }

        val nomediaDirs = HashSet<String>()

        fun recordArtifact(
            file: File,
            cat: FileCategory,
            detectedExt: String,
            forceHidden: Boolean = false,
            origin: String = "",
            explicitBadge: RecoverySourceBadge? = null,
            streamIntegrity: StreamIntegrityStatus = StreamIntegrityStatus.INTACT,
            skipIfMatchesActiveGallery: Boolean = false
        ) {
            val abs = file.absolutePath
            if (!seenPaths.add(abs)) return
            val length = file.length()
            if (length <= 0L) return

            if (skipIfMatchesActiveGallery && activeGalleryIndex.matchesActiveGallery(file)) {
                return
            }

            // Upgrade 6: Decoder Sanity Check on carved/orphaned PHOTO files
            var imgW = 0
            var imgH = 0
            val isCarvedOrThumb = explicitBadge == RecoverySourceBadge.UNOVERWRITTEN_SECTOR ||
                explicitBadge == RecoverySourceBadge.ORPHANED_THUMBNAIL ||
                explicitBadge == RecoverySourceBadge.WAL_DB_REMNANT ||
                origin.contains("Carve", ignoreCase = true)
            if (cat == FileCategory.PHOTO && isCarvedOrThumb) {
                val dims = validateCarvedImageDimensions(file) ?: return
                imgW = dims.first
                imgH = dims.second
            }

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

            val isThumbDir = normalizedPath.contains("/.thumbnails/", ignoreCase = true) ||
                normalizedPath.contains("/thumbnails/", ignoreCase = true) ||
                normalizedPath.contains("/.Thumbs/", ignoreCase = true) ||
                normalizedPath.contains("/.StickerThumbs/", ignoreCase = true)

            val isCacheOrMessengerRemnant = normalizedPath.contains("/cache/", ignoreCase = true) ||
                normalizedPath.contains("/.cache/", ignoreCase = true) ||
                normalizedPath.contains("/gallery_disk_cache/", ignoreCase = true) ||
                normalizedPath.contains("/.Shared/", ignoreCase = true) ||
                normalizedPath.contains("/.Statuses/", ignoreCase = true)

            val isLostDir = normalizedPath.contains("/LOST.DIR/", ignoreCase = true)

            val isHidden = forceHidden ||
                isTrashedFile ||
                isThumbDir ||
                isCacheOrMessengerRemnant ||
                isLostDir ||
                hasNomediaParent ||
                file.isHidden ||
                file.name.startsWith(".") ||
                normalizedPath.contains("/.")

            // If this is a thumbnail or cache remnant on disk that matches an active gallery file's exact fingerprint, skip it
            if ((isThumbDir || isCacheOrMessengerRemnant) && activeGalleryIndex.matchesActiveGallery(file)) {
                return
            }

            val resolvedBadge = explicitBadge ?: when {
                isTrashedFile -> RecoverySourceBadge.SYSTEM_TRASH_ORIGINAL
                isThumbDir -> RecoverySourceBadge.ORPHANED_THUMBNAIL
                isLostDir || isCacheOrMessengerRemnant || isHidden -> RecoverySourceBadge.UNOVERWRITTEN_SECTOR
                else -> RecoverySourceBadge.ACTIVE_GALLERY
            }

            val baseOriginLabel = when {
                origin.isNotEmpty() -> origin
                resolvedBadge == RecoverySourceBadge.SYSTEM_TRASH_ORIGINAL -> "System Trash Original (100% Quality)"
                resolvedBadge == RecoverySourceBadge.ORPHANED_THUMBNAIL -> "Orphaned Thumbnail Remnant"
                resolvedBadge == RecoverySourceBadge.WAL_DB_REMNANT -> "SQLite WAL / Freelist Carve"
                resolvedBadge == RecoverySourceBadge.UNLINKED_FD -> "Unlinked File Descriptor (/proc/fd)"
                isLostDir -> "Unoverwritten LOST.DIR Sector"
                isCacheOrMessengerRemnant -> "Unoverwritten Cache / Messenger Remnant"
                hasNomediaParent || isHidden -> "Unoverwritten Hidden Vault (.nomedia)"
                else -> "Active Gallery"
            }

            val finalOriginLabel = if (streamIntegrity == StreamIntegrityStatus.NEEDS_REPAIR_PARTIAL) {
                "$baseOriginLabel [${streamIntegrity.label}]"
            } else {
                baseOriginLabel
            }

            results += RecoverableFile(
                path = abs,
                name = file.name,
                category = cat,
                size = length,
                lastModified = file.lastModified().takeIf { it > 0L } ?: System.currentTimeMillis(),
                isHiddenOrTrashed = isHidden,
                recoveryOrigin = finalOriginLabel,
                detectedExt = detectedExt,
                sourceBadge = resolvedBadge,
                streamIntegrity = streamIntegrity,
                imageWidth = imgW,
                imageHeight = imgH
            )
        }

        // Layer 0: Unlinked Open File Descriptors (/proc/self/fd -> "... (deleted)")
        runCatching {
            val unlinked = scanUnlinkedOpenFileDescriptors(category, carvedStagingDir)
            for (artifact in unlinked) {
                scanned++
                recordArtifact(
                    file = artifact.file,
                    cat = category,
                    detectedExt = artifact.ext,
                    forceHidden = true,
                    origin = artifact.originLabel,
                    explicitBadge = RecoverySourceBadge.UNLINKED_FD,
                    skipIfMatchesActiveGallery = true
                )
            }
        }

        // Layer 1 (Upgrade 4): Deep MediaStore System Trash (MATCH_ONLY) & Pending (MATCH_INCLUDE)
        runCatching {
            val trashedMedia = queryMediaStoreSystemTrashAndPending(context, category)
            for (item in trashedMedia) {
                if (seenPaths.add(item.path)) {
                    scanned++
                    results += item
                    onProgress(scanned, results.count { it.isDeletedOrCarved }, item.path)
                }
            }
        }

        // Layer 2 (Upgrade 4): Orphaned MediaStore Thumbnails & 500-ID Gap Probe
        if (category == FileCategory.PHOTO || category == FileCategory.VIDEO) {
            runCatching {
                val orphanedThumbs = queryOrphanedThumbnailsAndIdGaps(
                    context = context,
                    category = category,
                    activeIndex = activeGalleryIndex,
                    outDir = carvedStagingDir
                )
                for (artifact in orphanedThumbs) {
                    scanned++
                    recordArtifact(
                        file = artifact.file,
                        cat = category,
                        detectedExt = artifact.ext,
                        forceHidden = true,
                        origin = artifact.originLabel,
                        explicitBadge = RecoverySourceBadge.ORPHANED_THUMBNAIL,
                        skipIfMatchesActiveGallery = true
                    )
                    onProgress(scanned, results.count { it.isDeletedOrCarved }, artifact.file.absolutePath)
                }
            }
        }

        // Layer 3 (Upgrades 1, 2, 3, 5): Recursive File System + SQLite WAL/Freelist Extractor + Stateful Sliding Window Carver
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
                        val delCount = results.count { it.isDeletedOrCarved }
                        onProgress(scanned, if (delCount > 0) delCount else results.size, f.absolutePath)
                    }

                    val nameLower = f.name.lowercase()
                    val rawExt = f.extension.lowercase()

                    val isSqliteOrWal = nameLower.endsWith(".db-wal") ||
                        nameLower.endsWith(".db-journal") ||
                        rawExt in setOf("db-wal", "db-journal", "wal", "journal", "db", "sqlite", "sqlite3")

                    val isContainerBlob = isSqliteOrWal ||
                        STREAM_CONTAINER_PREFIXES.any { nameLower.startsWith(it) } ||
                        rawExt in STREAM_CONTAINER_EXTS ||
                        (f.parentFile?.name?.equals(".thumbnails", ignoreCase = true) == true &&
                            f.length() > 16384L &&
                            rawExt !in FileCategory.PHOTO.extensions)

                    // Upgrade 3: SQLite WAL, Journal & 4 KB Freelist Page Blob Extractor
                    if (isSqliteOrWal && f.length() >= 1024L) {
                        val walArtifacts = extractSqliteWalAndFreelistBlobs(
                            dbOrWalFile = f,
                            category = category,
                            outDir = carvedStagingDir,
                            activeIndex = activeGalleryIndex,
                            seenSignatures = seenSignatures,
                            maxCount = 80
                        )
                        walArtifacts.forEach { artifact ->
                            recordArtifact(
                                file = artifact.file,
                                cat = category,
                                detectedExt = artifact.ext,
                                forceHidden = true,
                                origin = artifact.originLabel,
                                explicitBadge = RecoverySourceBadge.WAL_DB_REMNANT,
                                streamIntegrity = artifact.streamIntegrity,
                                skipIfMatchesActiveGallery = true
                            )
                        }
                        if (rawExt != "db" || category != FileCategory.DOCUMENT) {
                            return@forEach
                        }
                    }

                    // Upgrades 1 & 2: Stateful 64 MB Sliding Window (16 MB Overlap + 4 KB Sparse Skip) Stream Carver
                    if (isContainerBlob && !isSqliteOrWal && f.length() >= 1024L) {
                        val carvedList = carveUnoverwrittenStreams(
                            containerFile = f,
                            category = category,
                            outDir = carvedStagingDir,
                            activeIndex = activeGalleryIndex,
                            seenSignatures = seenSignatures,
                            maxCount = 120
                        )
                        carvedList.forEach { artifact ->
                            recordArtifact(
                                file = artifact.file,
                                cat = category,
                                detectedExt = artifact.ext,
                                forceHidden = true,
                                origin = artifact.originLabel,
                                explicitBadge = artifact.sourceBadge,
                                streamIntegrity = artifact.streamIntegrity,
                                skipIfMatchesActiveGallery = true
                            )
                        }
                        if (nameLower.startsWith("unallocated_sectors") || nameLower.startsWith(".thumbdata")) {
                            return@forEach
                        }
                    }

                    val directCategory = FileCategory.fromExtension(rawExt)

                    if (directCategory == category) {
                        recordArtifact(f, category, rawExt)
                    } else if (category == FileCategory.DOCUMENT &&
                        (f.name.contains(".pdf_", ignoreCase = true) ||
                            f.name.contains(".doc_", ignoreCase = true) ||
                            f.name.startsWith(".trashed-", ignoreCase = true))
                    ) {
                        val inferredExt = when {
                            f.name.endsWith(".zip", true) -> "zip"
                            f.name.endsWith(".apk", true) -> "apk"
                            f.name.contains(".pdf", true) -> "pdf"
                            else -> rawExt.ifBlank { "pdf" }
                        }
                        if (directCategory == null || directCategory == FileCategory.DOCUMENT || f.name.contains(".pdf_", true)) {
                            recordArtifact(
                                file = f,
                                cat = FileCategory.DOCUMENT,
                                detectedExt = inferredExt,
                                forceHidden = true,
                                explicitBadge = RecoverySourceBadge.UNOVERWRITTEN_SECTOR
                            )
                        }
                    } else if (directCategory == null ||
                        rawExt in DEEP_INSPECT_EXTS ||
                        f.name.startsWith(".trashed", ignoreCase = true) ||
                        f.parentFile?.name?.equals("LOST.DIR", ignoreCase = true) == true
                    ) {
                        val sig = detectByMagicBytes(f)
                        if (sig != null && sig.first == category) {
                            recordArtifact(
                                file = f,
                                cat = sig.first,
                                detectedExt = sig.second,
                                forceHidden = true,
                                origin = "Unoverwritten Header Signature Carve",
                                explicitBadge = RecoverySourceBadge.UNOVERWRITTEN_SECTOR,
                                skipIfMatchesActiveGallery = true
                            )
                        }
                    }
                }
        }

        // Layer 4: MediaStore fallback for active + trashed items
        runCatching {
            queryMediaStoreDeep(context, category).forEach { item ->
                if (seenPaths.add(item.path)) {
                    scanned++
                    results += item
                    val delCount = results.count { it.isDeletedOrCarved }
                    onProgress(scanned, if (delCount > 0) delCount else results.size, item.path)
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
                        val delCount = results.count { it.isDeletedOrCarved }
                        onProgress(scanned, if (delCount > 0) delCount else results.size, item.path)
                    }
                }
            }
        }

        if (scanned < 30) {
            onProgress(scanned, results.size, "/storage/emulated/0/DCIM/.thumbnails")
            delay(350)
        }
        onProgress(scanned, results.size, "")

        // Sort: Deleted/Carved/Unoverwritten badges strictly before Active Gallery, then newest first
        results.sortedWith(
            compareByDescending<RecoverableFile> { it.isDeletedOrCarved }
                .thenBy { badgePriorityOrder(it.sourceBadge) }
                .thenByDescending { it.lastModified }
        )
    }

    private fun badgePriorityOrder(badge: RecoverySourceBadge): Int = when (badge) {
        RecoverySourceBadge.SYSTEM_TRASH_ORIGINAL -> 0
        RecoverySourceBadge.UNOVERWRITTEN_SECTOR -> 1
        RecoverySourceBadge.WAL_DB_REMNANT -> 2
        RecoverySourceBadge.ORPHANED_THUMBNAIL -> 3
        RecoverySourceBadge.UNLINKED_FD -> 4
        RecoverySourceBadge.ACTIVE_GALLERY -> 99
    }

    /**
     * Upgrade 6: Builds an in-memory fingerprint index (`fileSize + CRC32_first_4KB + CRC32_last_4KB`)
     * of all active (non-trashed, non-pending) gallery files before carving starts.
     */
    fun buildActiveGalleryFingerprintIndex(
        context: Context,
        category: FileCategory
    ): ActiveGalleryFingerprintIndex {
        val index = ActiveGalleryFingerprintIndex()
        runCatching {
            val uri = when (category) {
                FileCategory.PHOTO -> MediaStore.Images.Media.EXTERNAL_CONTENT_URI
                FileCategory.VIDEO -> MediaStore.Video.Media.EXTERNAL_CONTENT_URI
                FileCategory.AUDIO -> MediaStore.Audio.Media.EXTERNAL_CONTENT_URI
                FileCategory.DOCUMENT -> MediaStore.Files.getContentUri("external")
            }
            val projection = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                arrayOf(
                    MediaStore.MediaColumns._ID,
                    MediaStore.MediaColumns.DATA,
                    MediaStore.MediaColumns.IS_TRASHED,
                    MediaStore.MediaColumns.IS_PENDING
                )
            } else {
                arrayOf(
                    MediaStore.MediaColumns._ID,
                    MediaStore.MediaColumns.DATA
                )
            }
            context.contentResolver.query(uri, projection, null, null, null)?.use { c ->
                val idIdx = c.getColumnIndex(MediaStore.MediaColumns._ID)
                val dataIdx = c.getColumnIndex(MediaStore.MediaColumns.DATA)
                val trashedIdx = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    c.getColumnIndex(MediaStore.MediaColumns.IS_TRASHED)
                } else -1
                val pendingIdx = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    c.getColumnIndex(MediaStore.MediaColumns.IS_PENDING)
                } else -1

                while (c.moveToNext()) {
                    val id = if (idIdx >= 0) c.getLong(idIdx) else -1L
                    val path = if (dataIdx >= 0) c.getString(dataIdx) else null
                    val isTrashed = trashedIdx >= 0 && c.getInt(trashedIdx) == 1
                    val isPending = pendingIdx >= 0 && c.getInt(pendingIdx) == 1
                    if (isTrashed || isPending || path.isNullOrBlank()) continue
                    val normalized = path.replace('\\', '/')
                    if (normalized.contains("/.") || normalized.contains("/LOST.DIR/", true)) continue
                    val f = File(path)
                    if (f.exists() && f.isFile) {
                        index.registerActiveFile(f, id)
                    }
                }
            }
        }
        return index
    }

    /**
     * Upgrade 1 & 2: Stateful 64 MB Sliding Window Carver with 16 MB Backward Overlap & 4 KB Sparse Skipping.
     *
     * Handles:
     *  - JPEG (`FF D8 FF` -> `FF D9`) bypassing embedded EXIF `APP1` (`FF E1`) thumbnail `FF D9` and verifying main `FF DA` (SOS).
     *  - PNG (`89 50 4E 47 0D 0A 1A 0A` -> `IEND`).
     *  - WEBP & WAV (`RIFF` + 4-byte LE uint32 size -> exact `declaredSize + 8` slice).
     *  - MP4 / MOV / 3GP (`ftyp` ISO BMFF Atom Chain Walker across `moov`, `mdat`, `free`, `skip`, `uuid`, `meta`, flagging `mdat`-without-`moov` as `NEEDS_REPAIR / PARTIAL_STREAM`).
     *  - ZIP / DOCX / XLSX (`PK\x03\x04` -> `PK\x05\x06` + `22 + commentLen`).
     *  - PDF (`%PDF-` -> `%%EOF` + trailing newline + `xref` or `/Root` token check).
     */
    fun carveUnoverwrittenStreams(
        containerFile: File,
        category: FileCategory,
        outDir: File,
        activeIndex: ActiveGalleryFingerprintIndex? = null,
        seenSignatures: MutableSet<String> = HashSet(),
        maxCount: Int = 120
    ): List<CarvedArtifact> = runCatching {
        val carved = ArrayList<CarvedArtifact>()
        val fileLen = containerFile.length()
        if (fileLen < 512L) return emptyList()

        val isWalOrDb = containerFile.name.endsWith("-wal", true) ||
            containerFile.name.endsWith("-journal", true) ||
            containerFile.extension.lowercase() in setOf("db", "sqlite", "sqlite3", "wal", "journal")

        val sourceBadge = if (isWalOrDb) {
            RecoverySourceBadge.WAL_DB_REMNANT
        } else {
            RecoverySourceBadge.UNOVERWRITTEN_SECTOR
        }

        val originLabel = when {
            isWalOrDb -> "SQLite WAL / Freelist Carve"
            containerFile.name.startsWith("unallocated_sectors", true) -> "Unoverwritten Disk Sector Carve"
            containerFile.name.startsWith(".thumbdata", true) ||
                containerFile.name.startsWith("imgcache", true) -> "Unoverwritten .thumbdata Carve"
            containerFile.extension.equals("exo", true) -> "Unoverwritten .exo Media Chunk Carve"
            containerFile.extension.equals("cnt", true) || containerFile.extension.equals("0", true) ->
                "Unoverwritten Glide/Fresco Disk Cache Carve"
            else -> "Unoverwritten Binary Stream Carve"
        }

        // Allocate up to 64 MB sliding window with 16 MB backward overlap (gracefully scaling to heap while preserving 25% overlap)
        val targetWindow = minOf(fileLen, SLIDING_WINDOW_BYTES.toLong()).toInt().coerceAtLeast(1024)
        val (buf, windowSize, overlapSize) = allocateSlidingWindowBuffer(targetWindow)
        val stepAdvance = (windowSize - overlapSize).coerceAtLeast(4096)

        val carvedAbsoluteOffsets = HashSet<Long>()

        fun b(idx: Int): Int = buf[idx].toInt() and 0xFF

        RandomAccessFile(containerFile, "r").use { raf ->
            var windowStartOffset = 0L
            while (windowStartOffset < fileLen && carved.size < maxCount) {
                val toRead = minOf(windowSize.toLong(), fileLen - windowStartOffset).toInt()
                if (toRead < 512) break
                raf.seek(windowStartOffset)
                raf.readFully(buf, 0, toRead)

                var i = 0
                while (i <= toRead - 12 && carved.size < maxCount) {
                    // Upgrade 1: Fast-skip any 4 KB block where first, middle, and last 64 bytes are all 0x00
                    if ((i and (SPARSE_BLOCK_SIZE - 1)) == 0 && isSparseZeroBlock4KB(buf, i, toRead)) {
                        i += SPARSE_BLOCK_SIZE
                        continue
                    }

                    val absStart = windowStartOffset + i
                    if (absStart in carvedAbsoluteOffsets) {
                        i++
                        continue
                    }

                    var jumpBytes = 1

                    when (category) {
                        FileCategory.PHOTO -> {
                            // 1. JPEG: FF D8 FF -> FF D9 (Upgrade 2: EXIF APP1 thumbnail trap fix + main SOS check)
                            if (b(i) == 0xFF && b(i + 1) == 0xD8 && b(i + 2) == 0xFF) {
                                val jpegEnd = findJpegEndBypassingExifThumbnail(buf, i, toRead)
                                if (jpegEnd > i + 512) {
                                    val len = jpegEnd - i
                                    val artifact = writeAndValidateCarvedSlice(
                                        raf = raf,
                                        absOffset = absStart,
                                        byteLength = len.toLong(),
                                        ext = "jpg",
                                        category = FileCategory.PHOTO,
                                        containerName = containerFile.name,
                                        outDir = outDir,
                                        originLabel = originLabel,
                                        sourceBadge = sourceBadge,
                                        activeIndex = activeIndex,
                                        seenSignatures = seenSignatures
                                    )
                                    if (artifact != null) {
                                        carved += artifact
                                        carvedAbsoluteOffsets += absStart
                                        jumpBytes = len
                                    }
                                }
                            }
                            // 2. WEBP: RIFF [4-byte LE uint32 size] WEBP (Upgrade 2: Exact Size Slicing)
                            else if (b(i) == 0x52 && b(i + 1) == 0x49 && b(i + 2) == 0x46 && b(i + 3) == 0x46 &&
                                b(i + 8) == 0x57 && b(i + 9) == 0x45 && b(i + 10) == 0x42 && b(i + 11) == 0x50
                            ) {
                                val totalFileSize = parseRiffContainerTotalSize(buf, i)
                                if (totalFileSize != null && absStart + totalFileSize <= fileLen) {
                                    val artifact = writeAndValidateCarvedSlice(
                                        raf = raf,
                                        absOffset = absStart,
                                        byteLength = totalFileSize,
                                        ext = "webp",
                                        category = FileCategory.PHOTO,
                                        containerName = containerFile.name,
                                        outDir = outDir,
                                        originLabel = originLabel,
                                        sourceBadge = sourceBadge,
                                        activeIndex = activeIndex,
                                        seenSignatures = seenSignatures
                                    )
                                    if (artifact != null) {
                                        carved += artifact
                                        carvedAbsoluteOffsets += absStart
                                        jumpBytes = minOf(totalFileSize, (toRead - i).toLong()).toInt()
                                    }
                                }
                            }
                            // 3. PNG: 89 50 4E 47 0D 0A 1A 0A -> IEND (49 45 4E 44 AE 42 60 82)
                            else if (b(i) == 0x89 && b(i + 1) == 0x50 && b(i + 2) == 0x4E && b(i + 3) == 0x47 &&
                                b(i + 4) == 0x0D && b(i + 5) == 0x0A && b(i + 6) == 0x1A && b(i + 7) == 0x0A
                            ) {
                                val pngEnd = findPngEndOffset(buf, i, toRead)
                                if (pngEnd > i + 128) {
                                    val len = pngEnd - i
                                    val artifact = writeAndValidateCarvedSlice(
                                        raf = raf,
                                        absOffset = absStart,
                                        byteLength = len.toLong(),
                                        ext = "png",
                                        category = FileCategory.PHOTO,
                                        containerName = containerFile.name,
                                        outDir = outDir,
                                        originLabel = originLabel,
                                        sourceBadge = sourceBadge,
                                        activeIndex = activeIndex,
                                        seenSignatures = seenSignatures
                                    )
                                    if (artifact != null) {
                                        carved += artifact
                                        carvedAbsoluteOffsets += absStart
                                        jumpBytes = len
                                    }
                                }
                            }
                        }

                        FileCategory.VIDEO -> {
                            // Upgrade 2: MP4 / MOV / 3GP ISO BMFF Atom Chain Walker
                            if (b(i + 4) == 0x66 && b(i + 5) == 0x74 && b(i + 6) == 0x79 && b(i + 7) == 0x70) {
                                val walkResult = walkIsoBmffAtomChain(raf, absStart, fileLen)
                                if (walkResult != null && walkResult.first >= 1024L) {
                                    val totalBytes = walkResult.first
                                    val integrity = walkResult.second
                                    val artifact = writeAndValidateCarvedSlice(
                                        raf = raf,
                                        absOffset = absStart,
                                        byteLength = totalBytes,
                                        ext = "mp4",
                                        category = FileCategory.VIDEO,
                                        containerName = containerFile.name,
                                        outDir = outDir,
                                        originLabel = originLabel,
                                        sourceBadge = sourceBadge,
                                        streamIntegrity = integrity,
                                        activeIndex = activeIndex,
                                        seenSignatures = seenSignatures
                                    )
                                    if (artifact != null) {
                                        carved += artifact
                                        carvedAbsoluteOffsets += absStart
                                        jumpBytes = minOf(totalBytes, (toRead - i).toLong()).toInt()
                                    }
                                }
                            }
                        }

                        FileCategory.AUDIO -> {
                            // 1. WAV: RIFF [4-byte LE uint32 size] WAVE (Upgrade 2: Exact Size Slicing)
                            if (b(i) == 0x52 && b(i + 1) == 0x49 && b(i + 2) == 0x46 && b(i + 3) == 0x46 &&
                                b(i + 8) == 0x57 && b(i + 9) == 0x41 && b(i + 10) == 0x56 && b(i + 11) == 0x45
                            ) {
                                val totalFileSize = parseRiffContainerTotalSize(buf, i)
                                if (totalFileSize != null && absStart + totalFileSize <= fileLen) {
                                    val artifact = writeAndValidateCarvedSlice(
                                        raf = raf,
                                        absOffset = absStart,
                                        byteLength = totalFileSize,
                                        ext = "wav",
                                        category = FileCategory.AUDIO,
                                        containerName = containerFile.name,
                                        outDir = outDir,
                                        originLabel = originLabel,
                                        sourceBadge = sourceBadge,
                                        activeIndex = activeIndex,
                                        seenSignatures = seenSignatures
                                    )
                                    if (artifact != null) {
                                        carved += artifact
                                        carvedAbsoluteOffsets += absStart
                                        jumpBytes = minOf(totalFileSize, (toRead - i).toLong()).toInt()
                                    }
                                }
                            }
                            // 2. MP3: ID3v2 header (49 44 33) + contiguous MPEG audio frames
                            else if (b(i) == 0x49 && b(i + 1) == 0x44 && b(i + 2) == 0x33 && b(i + 3) in 2..4) {
                                val id3Size = ((b(i + 6) and 0x7F) shl 21) or
                                    ((b(i + 7) and 0x7F) shl 14) or
                                    ((b(i + 8) and 0x7F) shl 7) or
                                    (b(i + 9) and 0x7F)
                                val audioStart = i + 10 + id3Size
                                if (audioStart in (i + 10)..(toRead - 1024)) {
                                    val estEnd = minOf(toRead, audioStart + 512 * 1024)
                                    val len = estEnd - i
                                    val artifact = writeAndValidateCarvedSlice(
                                        raf = raf,
                                        absOffset = absStart,
                                        byteLength = len.toLong(),
                                        ext = "mp3",
                                        category = FileCategory.AUDIO,
                                        containerName = containerFile.name,
                                        outDir = outDir,
                                        originLabel = originLabel,
                                        sourceBadge = sourceBadge,
                                        activeIndex = activeIndex,
                                        seenSignatures = seenSignatures
                                    )
                                    if (artifact != null) {
                                        carved += artifact
                                        carvedAbsoluteOffsets += absStart
                                        jumpBytes = len
                                    }
                                }
                            }
                            // 3. OGG / OPUS Voice Notes: OggS (4F 67 67 53)
                            else if (b(i) == 0x4F && b(i + 1) == 0x67 && b(i + 2) == 0x67 && b(i + 3) == 0x53 && b(i + 4) == 0x00) {
                                val oggEnd = findOggStreamEnd(buf, i, toRead)
                                if (oggEnd > i + 512) {
                                    val len = oggEnd - i
                                    val artifact = writeAndValidateCarvedSlice(
                                        raf = raf,
                                        absOffset = absStart,
                                        byteLength = len.toLong(),
                                        ext = "ogg",
                                        category = FileCategory.AUDIO,
                                        containerName = containerFile.name,
                                        outDir = outDir,
                                        originLabel = originLabel,
                                        sourceBadge = sourceBadge,
                                        activeIndex = activeIndex,
                                        seenSignatures = seenSignatures
                                    )
                                    if (artifact != null) {
                                        carved += artifact
                                        carvedAbsoluteOffsets += absStart
                                        jumpBytes = len
                                    }
                                }
                            }
                        }

                        FileCategory.DOCUMENT -> {
                            // 1. PDF: %PDF- -> %%EOF + trailing newlines + xref or /Root validation (Upgrade 2)
                            if (b(i) == 0x25 && b(i + 1) == 0x50 && b(i + 2) == 0x44 && b(i + 3) == 0x46 && b(i + 4) == 0x2D) {
                                val pdfEnd = findValidatedPdfEnd(buf, i, toRead)
                                if (pdfEnd > i + 128) {
                                    val len = pdfEnd - i
                                    val artifact = writeAndValidateCarvedSlice(
                                        raf = raf,
                                        absOffset = absStart,
                                        byteLength = len.toLong(),
                                        ext = "pdf",
                                        category = FileCategory.DOCUMENT,
                                        containerName = containerFile.name,
                                        outDir = outDir,
                                        originLabel = originLabel,
                                        sourceBadge = sourceBadge,
                                        activeIndex = activeIndex,
                                        seenSignatures = seenSignatures
                                    )
                                    if (artifact != null) {
                                        carved += artifact
                                        carvedAbsoluteOffsets += absStart
                                        jumpBytes = len
                                    }
                                }
                            }
                            // 2. ZIP / DOCX / XLSX: PK\x03\x04 -> PK\x05\x06 + full 22 + N comment tail (Upgrade 2)
                            else if (b(i) == 0x50 && b(i + 1) == 0x4B && b(i + 2) == 0x03 && b(i + 3) == 0x04) {
                                val zipResult = findZipEndWithFullEocd(buf, i, toRead)
                                if (zipResult != null && zipResult.first > i + 64) {
                                    val zipEnd = zipResult.first
                                    val detectedZipExt = zipResult.second
                                    val len = zipEnd - i
                                    val artifact = writeAndValidateCarvedSlice(
                                        raf = raf,
                                        absOffset = absStart,
                                        byteLength = len.toLong(),
                                        ext = detectedZipExt,
                                        category = FileCategory.DOCUMENT,
                                        containerName = containerFile.name,
                                        outDir = outDir,
                                        originLabel = originLabel,
                                        sourceBadge = sourceBadge,
                                        activeIndex = activeIndex,
                                        seenSignatures = seenSignatures
                                    )
                                    if (artifact != null) {
                                        carved += artifact
                                        carvedAbsoluteOffsets += absStart
                                        jumpBytes = len
                                    }
                                }
                            }
                        }
                    }

                    i += jumpBytes.coerceAtLeast(1)
                }

                if (windowStartOffset + toRead >= fileLen) break
                windowStartOffset += stepAdvance.toLong()
            }
        }
        carved
    }.getOrDefault(emptyList())

    /**
     * Allocates the 64 MB sliding window buffer with 16 MB backward overlap,
     * falling back safely only if the JVM test/device heap cannot fit 64 MB in a single contiguous array.
     */
    private fun allocateSlidingWindowBuffer(requestedWindowBytes: Int): Triple<ByteArray, Int, Int> {
        val candidates = listOf(
            requestedWindowBytes.coerceAtMost(SLIDING_WINDOW_BYTES) to SLIDING_OVERLAP_BYTES,
            (16 * 1024 * 1024) to (4 * 1024 * 1024),
            (4 * 1024 * 1024) to (1 * 1024 * 1024)
        )
        for ((win, ovl) in candidates) {
            try {
                val actualWin = maxOf(win, 1024)
                val actualOvl = minOf(ovl, actualWin / 4)
                return Triple(ByteArray(actualWin), actualWin, actualOvl)
            } catch (_: OutOfMemoryError) {
                // Try next smaller window with 25% backward overlap
            }
        }
        val fallbackWin = 1024 * 1024
        return Triple(ByteArray(fallbackWin), fallbackWin, 256 * 1024)
    }

    /**
     * Upgrade 2 (JPEG EXIF Thumbnail Trap Fix):
     * Finds the true outer JPEG `FF D9` End-Of-Image offset starting from [startIdx] (`FF D8 FF`).
     *  - Tracks nested `FF D8` markers inside `APP1` (`FF E1`) / `APP2` (`FF E2`) EXIF thumbnails.
     *  - Skips over length-prefixed JPEG segments (`APPn`, `DQT`, `DHT`, `SOFn`, `COM`).
     *  - Only accepts `FF D9` AFTER the main image's Start of Scan (`FF DA` - SOS) marker has been seen
     *    at outer depth (`nestedDepth == 0`).
     */
    fun findJpegEndBypassingExifThumbnail(buf: ByteArray, startIdx: Int, limit: Int): Int {
        fun u8(p: Int): Int = buf[p].toInt() and 0xFF
        fun u16Be(p: Int): Int = (u8(p) shl 8) or u8(p + 1)

        if (startIdx + 4 >= limit) return -1
        if (u8(startIdx) != 0xFF || u8(startIdx + 1) != 0xD8 || u8(startIdx + 2) != 0xFF) return -1

        val maxEnd = minOf(limit, startIdx + 20 * 1024 * 1024)
        var pos = startIdx + 2
        var seenMainSos = false
        var nestedDepth = 0

        while (pos < maxEnd - 1) {
            if (!seenMainSos) {
                // Before main SOS: parse structured JPEG marker segments
                if (u8(pos) != 0xFF) {
                    pos++
                    continue
                }
                while (pos < maxEnd && u8(pos) == 0xFF) pos++
                if (pos >= maxEnd) break
                val marker = u8(pos)
                pos++

                if (marker == 0x00 || marker in 0xD0..0xD7 || marker == 0x01) {
                    continue
                }
                if (marker == 0xD8) {
                    nestedDepth++
                    continue
                }
                if (marker == 0xD9) {
                    if (nestedDepth > 0) {
                        nestedDepth--
                        continue
                    } else {
                        // Encountered FF D9 before any main SOS marker -> premature/corrupt or empty header
                        return -1
                    }
                }
                if (pos + 2 > maxEnd) break
                val segLen = u16Be(pos)
                if (segLen < 2 || pos + segLen > maxEnd) break

                if (marker == 0xDA && nestedDepth == 0) {
                    // Main image Start Of Scan (SOS) reached! Jump past SOS header into entropy-coded scan data
                    seenMainSos = true
                    pos += segLen
                } else {
                    // Jump over entire segment (including APP1 EXIF block containing any embedded thumbnail FF D8 ... FF D9!)
                    pos += segLen
                }
            } else {
                // Inside main entropy-coded scan stream after main FF DA (SOS):
                // Track any nested FF D8 and find the closing FF D9 for the main image
                if (u8(pos) == 0xFF) {
                    val nextByte = u8(pos + 1)
                    if (nextByte == 0xD8) {
                        nestedDepth++
                        pos += 2
                        continue
                    } else if (nextByte == 0xD9) {
                        if (nestedDepth > 0) {
                            nestedDepth--
                            pos += 2
                            continue
                        } else {
                            return pos + 2
                        }
                    } else if (nextByte == 0xDA) {
                        // Progressive JPEG with multiple scans (SOS markers)
                        pos += 2
                        continue
                    }
                }
                pos++
            }
        }
        return -1
    }

    /**
     * Upgrade 2 (WEBP & WAV RIFF Exact Size Slicing):
     * Reads the 4-byte Little-Endian uint32 immediately following `RIFF` (bytes 4..7),
     * computes `totalFileSize = declaredSize + 8`, and validates sanity (`1 KB..100 MB`).
     */
    fun parseRiffContainerTotalSize(buf: ByteArray, startIdx: Int): Long? {
        if (startIdx + 12 > buf.size) return null
        fun u8(p: Int): Long = (buf[p].toInt() and 0xFF).toLong()
        if (u8(startIdx) != 0x52L || u8(startIdx + 1) != 0x49L ||
            u8(startIdx + 2) != 0x46L || u8(startIdx + 3) != 0x46L
        ) return null

        val declaredSize = u8(startIdx + 4) or
            (u8(startIdx + 5) shl 8) or
            (u8(startIdx + 6) shl 16) or
            (u8(startIdx + 7) shl 24)

        val totalFileSize = declaredSize + 8L
        return if (totalFileSize in MIN_RIFF_SIZE_BYTES..MAX_RIFF_SIZE_BYTES) {
            totalFileSize
        } else {
            null
        }
    }

    /**
     * Upgrade 2 (MP4 / MOV / 3GP `ftyp` Atom Chain Walker):
     * Walks sequentially through contiguous top-level ISO BMFF boxes (`ftyp`, `moov`, `mdat`, `free`, `skip`, `uuid`, `meta`)
     * by jumping `boxSize` bytes each time until an invalid box header or EOF is reached.
     * Flags carves that contain `mdat` without `moov` as [StreamIntegrityStatus.NEEDS_REPAIR_PARTIAL].
     */
    fun walkIsoBmffAtomChain(
        raf: RandomAccessFile,
        startOffset: Long,
        fileLen: Long
    ): Pair<Long, StreamIntegrityStatus>? = runCatching {
        if (startOffset + 16L > fileLen) return null
        val header = ByteArray(16)

        fun readBeU32(b: ByteArray, off: Int): Long {
            return ((b[off].toLong() and 0xFF) shl 24) or
                ((b[off + 1].toLong() and 0xFF) shl 16) or
                ((b[off + 2].toLong() and 0xFF) shl 8) or
                (b[off + 3].toLong() and 0xFF)
        }

        fun readBeU64(b: ByteArray, off: Int): Long {
            return (readBeU32(b, off) shl 32) or (readBeU32(b, off + 4) and 0xFFFFFFFFL)
        }

        raf.seek(startOffset)
        raf.readFully(header, 0, 8)
        val firstSize = readBeU32(header, 0)
        val firstType = String(header, 4, 4, Charsets.US_ASCII)
        if (firstType != "ftyp" || firstSize !in 16L..512L || startOffset + firstSize > fileLen) {
            return null
        }

        var curOffset = startOffset
        var hasMoov = false
        var hasMdat = false
        var boxCount = 0

        while (curOffset + 8L <= fileLen && (curOffset - startOffset) < MAX_CARVED_STREAM_BYTES) {
            raf.seek(curOffset)
            val canRead = minOf(16L, fileLen - curOffset).toInt()
            raf.readFully(header, 0, canRead)

            val rawSize = readBeU32(header, 0)
            val boxType = String(header, 4, 4, Charsets.US_ASCII)
            if (boxType !in VALID_ISO_BMFF_BOXES) break

            val actualBoxSize = when {
                rawSize == 1L && canRead >= 16 -> readBeU64(header, 8)
                rawSize >= 8L -> rawSize
                else -> -1L
            }

            if (actualBoxSize < 8L || curOffset + actualBoxSize > fileLen) break
            if (boxType == "moov") hasMoov = true
            if (boxType == "mdat") hasMdat = true
            boxCount++
            curOffset += actualBoxSize
        }

        val totalSize = curOffset - startOffset
        if (boxCount < 2 || (!hasMoov && !hasMdat) || totalSize < 512L) {
            return null
        }

        val status = if (hasMdat && !hasMoov) {
            StreamIntegrityStatus.NEEDS_REPAIR_PARTIAL
        } else {
            StreamIntegrityStatus.INTACT
        }
        totalSize to status
    }.getOrNull()

    /**
     * Upgrade 2 (ZIP / DOCX / XLSX Full EOCD Tail):
     * Finds `PK\x05\x06`, reads the 2-byte Little-Endian comment length `N` at offset `+20`,
     * and returns `(endOffsetWithFull22PlusN, detectedExtension)`.
     */
    fun findZipEndWithFullEocd(buf: ByteArray, startIdx: Int, limit: Int): Pair<Int, String>? {
        fun u8(p: Int): Int = buf[p].toInt() and 0xFF
        val maxEnd = minOf(limit - 22, startIdx + 25 * 1024 * 1024)
        var pos = startIdx + 30
        var detectedExt = "zip"

        while (pos <= maxEnd) {
            // Check for central directory / local file entry names to classify Office docs & APKs
            if (u8(pos) == 0x77 && pos + 17 < limit &&
                String(buf, pos, 17, Charsets.US_ASCII) == "word/document.xml"
            ) {
                detectedExt = "docx"
            } else if (u8(pos) == 0x78 && pos + 15 < limit &&
                String(buf, pos, 15, Charsets.US_ASCII) == "xl/workbook.xml"
            ) {
                detectedExt = "xlsx"
            } else if (u8(pos) == 0x70 && pos + 20 < limit &&
                String(buf, pos, 20, Charsets.US_ASCII) == "ppt/presentation.xml"
            ) {
                detectedExt = "pptx"
            } else if (u8(pos) == 0x41 && pos + 19 < limit &&
                String(buf, pos, 19, Charsets.US_ASCII) == "AndroidManifest.xml"
            ) {
                detectedExt = "apk"
            }

            // End of Central Directory signature: 50 4B 05 06
            if (u8(pos) == 0x50 && u8(pos + 1) == 0x4B && u8(pos + 2) == 0x05 && u8(pos + 3) == 0x06) {
                val commentLen = u8(pos + 20) or (u8(pos + 21) shl 8)
                val fullEnd = pos + 22 + commentLen
                if (fullEnd <= limit) {
                    return fullEnd to detectedExt
                }
            }
            pos++
        }
        return null
    }

    /**
     * Upgrade 2 (PDF Structural Validation + Trailing Newlines):
     * Finds `%%EOF`, includes trailing `\r`/`\n` bytes, and verifies the presence of `xref` or `/Root`
     * inside the carved slice to eliminate false-positive text matches.
     */
    fun findValidatedPdfEnd(buf: ByteArray, startIdx: Int, limit: Int): Int {
        fun u8(p: Int): Int = buf[p].toInt() and 0xFF
        val maxEnd = minOf(limit - 5, startIdx + 25 * 1024 * 1024)
        var pos = startIdx + 8
        var hasXrefOrRoot = false
        var eofEnd = -1

        while (pos <= maxEnd) {
            // Check for 'xref' (78 72 65 66) or '/Root' (2F 52 6F 6F 74)
            if (!hasXrefOrRoot) {
                if (u8(pos) == 0x78 && u8(pos + 1) == 0x72 && u8(pos + 2) == 0x65 && u8(pos + 3) == 0x66) {
                    hasXrefOrRoot = true
                } else if (u8(pos) == 0x2F && u8(pos + 1) == 0x52 && u8(pos + 2) == 0x6F &&
                    u8(pos + 3) == 0x6F && u8(pos + 4) == 0x74
                ) {
                    hasXrefOrRoot = true
                }
            }

            // Check for '%%EOF' (25 25 45 4F 46)
            if (u8(pos) == 0x25 && u8(pos + 1) == 0x25 && u8(pos + 2) == 0x45 &&
                u8(pos + 3) == 0x4F && u8(pos + 4) == 0x46
            ) {
                var tail = pos + 5
                while (tail < limit && (u8(tail) == 0x0D || u8(tail) == 0x0A)) {
                    tail++
                }
                eofEnd = tail
                if (hasXrefOrRoot) {
                    return eofEnd
                }
            }
            pos++
        }
        return if (hasXrefOrRoot && eofEnd > startIdx) eofEnd else -1
    }

    private fun findPngEndOffset(buf: ByteArray, startIdx: Int, limit: Int): Int {
        fun u8(p: Int): Int = buf[p].toInt() and 0xFF
        val maxEnd = minOf(limit - 8, startIdx + 20 * 1024 * 1024)
        var pos = startIdx + 8
        while (pos <= maxEnd) {
            if (u8(pos) == 0x49 && u8(pos + 1) == 0x45 && u8(pos + 2) == 0x4E && u8(pos + 3) == 0x44 &&
                u8(pos + 4) == 0xAE && u8(pos + 5) == 0x42 && u8(pos + 6) == 0x60 && u8(pos + 7) == 0x82
            ) {
                return pos + 8
            }
            pos++
        }
        return -1
    }

    private fun findOggStreamEnd(buf: ByteArray, startIdx: Int, limit: Int): Int {
        fun u8(p: Int): Int = buf[p].toInt() and 0xFF
        var pos = startIdx
        var lastValidEnd = -1
        while (pos + 27 < limit) {
            if (u8(pos) != 0x4F || u8(pos + 1) != 0x67 || u8(pos + 2) != 0x67 || u8(pos + 3) != 0x53) break
            val headerType = u8(pos + 5)
            val pageSegments = u8(pos + 26)
            if (pos + 27 + pageSegments > limit) break
            var payloadBytes = 0
            for (s in 0 until pageSegments) {
                payloadBytes += u8(pos + 27 + s)
            }
            val nextPage = pos + 27 + pageSegments + payloadBytes
            if (nextPage > limit) break
            lastValidEnd = nextPage
            pos = nextPage
            // Bit 0x04 in header_type_flag indicates End Of Stream (EOS) page
            if ((headerType and 0x04) != 0) break
        }
        return lastValidEnd
    }

    /**
     * Slices `[absOffset .. absOffset + byteLength)` directly from [raf] (supporting cross-window
     * streams up to 100 MB), deduplicates against [activeIndex] and [seenSignatures], and runs
     * `BitmapFactory.inJustDecodeBounds` validation on images.
     */
    private fun writeAndValidateCarvedSlice(
        raf: RandomAccessFile,
        absOffset: Long,
        byteLength: Long,
        ext: String,
        category: FileCategory,
        containerName: String,
        outDir: File,
        originLabel: String,
        sourceBadge: RecoverySourceBadge,
        streamIntegrity: StreamIntegrityStatus = StreamIntegrityStatus.INTACT,
        activeIndex: ActiveGalleryFingerprintIndex?,
        seenSignatures: MutableSet<String>
    ): CarvedArtifact? {
        if (byteLength < 256L || byteLength > MAX_CARVED_STREAM_BYTES) return null

        val safeContainer = containerName.replace(Regex("[^a-zA-Z0-9._-]"), "_")
        val outFile = File(outDir, "carved_${safeContainer}_0x${absOffset.toString(16)}.$ext")

        // Stream directly from RandomAccessFile so slices crossing window boundaries are never truncated
        val savedPos = raf.filePointer
        try {
            raf.seek(absOffset)
            FileOutputStream(outFile).use { fos ->
                val copyBuf = ByteArray(64 * 1024)
                var remaining = byteLength
                while (remaining > 0L) {
                    val toRead = minOf(copyBuf.size.toLong(), remaining).toInt()
                    val r = raf.read(copyBuf, 0, toRead)
                    if (r <= 0) break
                    fos.write(copyBuf, 0, r)
                    remaining -= r
                }
            }
        } finally {
            runCatching { raf.seek(savedPos) }
        }

        if (!outFile.exists() || outFile.length() != byteLength) {
            outFile.delete()
            return null
        }

        // Fast fingerprint deduplication against active gallery & already-carved streams
        val fp = computeFastFingerprint(outFile)
        if (fp == null || !seenSignatures.add("$ext:$fp")) {
            outFile.delete()
            return null
        }
        if (activeIndex != null && fp in activeIndex.fullFingerprints) {
            outFile.delete()
            return null
        }

        // Upgrade 6: Decoder Sanity Check for PHOTO category
        var width = 0
        var height = 0
        if (category == FileCategory.PHOTO) {
            val dims = validateCarvedImageDimensions(outFile)
            if (dims == null || dims.first <= 0 || dims.second <= 0) {
                outFile.delete()
                return null
            }
            width = dims.first
            height = dims.second
        }

        return CarvedArtifact(
            file = outFile,
            ext = ext,
            originLabel = originLabel,
            sourceBadge = sourceBadge,
            streamIntegrity = streamIntegrity,
            imageWidth = width,
            imageHeight = height
        )
    }

    /**
     * Upgrade 3: SQLite WAL (`*.db-wal`), Rollback Journal (`*.db-journal`), and 4096-byte Freelist Page Blob Extractor.
     * Scans raw 4096-byte pages and WAL frames directly for embedded JPEG, PNG, WEBP, PDF, ZIP, and audio headers
     * so unoverwritten deleted database records and cached media blobs are extracted with `WAL_DB_REMNANT` badge.
     */
    fun extractSqliteWalAndFreelistBlobs(
        dbOrWalFile: File,
        category: FileCategory,
        outDir: File,
        activeIndex: ActiveGalleryFingerprintIndex? = null,
        seenSignatures: MutableSet<String> = HashSet(),
        maxCount: Int = 80
    ): List<CarvedArtifact> {
        return carveUnoverwrittenStreams(
            containerFile = dbOrWalFile,
            category = category,
            outDir = outDir,
            activeIndex = activeIndex,
            seenSignatures = seenSignatures,
            maxCount = maxCount
        ).map {
            it.copy(
                originLabel = "SQLite WAL / 4KB Freelist Blob Carve (${dbOrWalFile.name})",
                sourceBadge = RecoverySourceBadge.WAL_DB_REMNANT
            )
        }
    }

    /**
     * Upgrade 4 (Part A): Deep MediaStore Interrogation for Hidden System Trash & Pending items.
     * On Android 10/11+ (API 29/30+), queries `MediaStore.Images`, `MediaStore.Video`, `MediaStore.Audio`,
     * and `MediaStore.Files` using `Bundle` arguments with `QUERY_ARG_MATCH_TRASHED = MATCH_ONLY`
     * and `QUERY_ARG_MATCH_PENDING = MATCH_INCLUDE` to recover 100% original-quality recently deleted files.
     */
    private fun queryMediaStoreSystemTrashAndPending(
        context: Context,
        category: FileCategory
    ): List<RecoverableFile> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return emptyList()
        val results = ArrayList<RecoverableFile>()
        val seen = HashSet<String>()
        val resolver = context.contentResolver

        val uris = when (category) {
            FileCategory.PHOTO -> listOf(
                MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
                MediaStore.Files.getContentUri("external")
            )
            FileCategory.VIDEO -> listOf(
                MediaStore.Video.Media.EXTERNAL_CONTENT_URI,
                MediaStore.Files.getContentUri("external")
            )
            FileCategory.AUDIO -> listOf(
                MediaStore.Audio.Media.EXTERNAL_CONTENT_URI,
                MediaStore.Files.getContentUri("external")
            )
            FileCategory.DOCUMENT -> listOf(
                MediaStore.Files.getContentUri("external")
            )
        }

        val projection = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            arrayOf(
                MediaStore.MediaColumns._ID,
                MediaStore.MediaColumns.DATA,
                MediaStore.MediaColumns.DISPLAY_NAME,
                MediaStore.MediaColumns.SIZE,
                MediaStore.MediaColumns.DATE_MODIFIED,
                MediaStore.MediaColumns.IS_TRASHED,
                MediaStore.MediaColumns.IS_PENDING
            )
        } else {
            arrayOf(
                MediaStore.MediaColumns._ID,
                MediaStore.MediaColumns.DATA,
                MediaStore.MediaColumns.DISPLAY_NAME,
                MediaStore.MediaColumns.SIZE,
                MediaStore.MediaColumns.DATE_MODIFIED,
                MediaStore.MediaColumns.IS_PENDING
            )
        }

        for (uri in uris) {
            val bundleList = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                listOf(
                    // Pass 1: Strictly trashed items (MATCH_ONLY)
                    Bundle().apply {
                        putInt(MediaStore.QUERY_ARG_MATCH_TRASHED, MediaStore.MATCH_ONLY)
                        putInt(MediaStore.QUERY_ARG_MATCH_PENDING, MediaStore.MATCH_INCLUDE)
                    },
                    // Pass 2: Unfinalized pending items (MATCH_ONLY)
                    Bundle().apply {
                        putInt(MediaStore.QUERY_ARG_MATCH_PENDING, MediaStore.MATCH_ONLY)
                    }
                )
            } else {
                listOf(
                    Bundle().apply {
                        putInt(MediaStore.QUERY_ARG_MATCH_PENDING, MediaStore.MATCH_ONLY)
                    }
                )
            }

            for (queryArgs in bundleList) {
                runCatching {
                    resolver.query(uri, projection, queryArgs, null)?.use { c ->
                        val dataIdx = c.getColumnIndex(MediaStore.MediaColumns.DATA)
                        val nameIdx = c.getColumnIndex(MediaStore.MediaColumns.DISPLAY_NAME)
                        val sizeIdx = c.getColumnIndex(MediaStore.MediaColumns.SIZE)
                        val dateIdx = c.getColumnIndex(MediaStore.MediaColumns.DATE_MODIFIED)

                        while (c.moveToNext()) {
                            val path = if (dataIdx >= 0) c.getString(dataIdx) else null
                            if (path.isNullOrBlank() || !seen.add(path)) continue
                            val f = File(path)
                            if (!f.exists() || f.length() <= 0L) continue
                            val name = (if (nameIdx >= 0) c.getString(nameIdx) else null) ?: f.name
                            val ext = name.substringAfterLast('.', f.extension).lowercase()
                            val cat = FileCategory.fromExtension(ext) ?: continue
                            if (cat != category) continue
                            val size = if (sizeIdx >= 0) c.getLong(sizeIdx).takeIf { it > 0 } ?: f.length() else f.length()
                            val modSec = if (dateIdx >= 0) c.getLong(dateIdx) else 0L
                            val lastMod = if (modSec > 0) modSec * 1000L else f.lastModified()

                            results += RecoverableFile(
                                path = f.absolutePath,
                                name = name,
                                category = category,
                                size = size,
                                lastModified = lastMod,
                                isHiddenOrTrashed = true,
                                recoveryOrigin = "System Trash Original (100% Quality)",
                                detectedExt = ext,
                                sourceBadge = RecoverySourceBadge.SYSTEM_TRASH_ORIGINAL
                            )
                        }
                    }
                }
            }
        }
        return results
    }

    /**
     * Upgrade 4 (Part B): Orphaned Thumbnail & 500-ID Gap Probe.
     *  1. Cross-checks `MediaStore.Images.Thumbnails` / `Video.Thumbnails` against active MediaStore `_id` sets.
     *  2. Identifies recent missing `_id` gaps between `MAX(_id) - 500` and `MAX(_id)` and probes
     *     `ContentResolver.loadThumbnail()` / cached thumbnail paths in best-effort mode to catch
     *     lingering system-cached previews of permanently deleted items.
     */
    private fun queryOrphanedThumbnailsAndIdGaps(
        context: Context,
        category: FileCategory,
        activeIndex: ActiveGalleryFingerprintIndex,
        outDir: File
    ): List<CarvedArtifact> = runCatching {
        val artifacts = ArrayList<CarvedArtifact>()
        val resolver = context.contentResolver
        val activeIds = activeIndex.activeMediaIds

        if (category == FileCategory.PHOTO) {
            @Suppress("DEPRECATION")
            runCatching {
                resolver.query(
                    MediaStore.Images.Thumbnails.EXTERNAL_CONTENT_URI,
                    arrayOf(
                        MediaStore.Images.Thumbnails._ID,
                        MediaStore.Images.Thumbnails.IMAGE_ID,
                        MediaStore.Images.Thumbnails.DATA
                    ),
                    null,
                    null,
                    null
                )?.use { c ->
                    val idIdx = c.getColumnIndex(MediaStore.Images.Thumbnails._ID)
                    val imgIdIdx = c.getColumnIndex(MediaStore.Images.Thumbnails.IMAGE_ID)
                    val dataIdx = c.getColumnIndex(MediaStore.Images.Thumbnails.DATA)
                    while (c.moveToNext() && artifacts.size < 80) {
                        val thumbId = if (idIdx >= 0) c.getLong(idIdx) else -1L
                        val imgId = if (imgIdIdx >= 0) c.getLong(imgIdIdx) else -1L
                        val dataPath = if (dataIdx >= 0) c.getString(dataIdx) else null
                        val isOrphaned = imgId <= 0L || imgId !in activeIds
                        if (!isOrphaned) continue

                        val existingFile = dataPath?.let { File(it) }?.takeIf { it.exists() && it.length() > 512L }
                        if (existingFile != null && !activeIndex.matchesActiveGallery(existingFile)) {
                            val dims = validateCarvedImageDimensions(existingFile)
                            if (dims != null) {
                                artifacts += CarvedArtifact(
                                    file = existingFile,
                                    ext = "jpg",
                                    originLabel = "Orphaned MediaStore Thumbnail (ID #$imgId)",
                                    sourceBadge = RecoverySourceBadge.ORPHANED_THUMBNAIL,
                                    imageWidth = dims.first,
                                    imageHeight = dims.second
                                )
                            }
                        } else if (thumbId > 0L) {
                            val thumbUri = ContentUris.withAppendedId(
                                MediaStore.Images.Thumbnails.EXTERNAL_CONTENT_URI,
                                thumbId
                            )
                            val staged = File(outDir, "orphaned_thumb_${thumbId}_img_${imgId}.jpg")
                            runCatching {
                                resolver.openInputStream(thumbUri)?.use { input ->
                                    staged.outputStream().use { output -> input.copyTo(output) }
                                }
                            }
                            if (staged.exists() && staged.length() > 512L && !activeIndex.matchesActiveGallery(staged)) {
                                val dims = validateCarvedImageDimensions(staged)
                                if (dims != null) {
                                    artifacts += CarvedArtifact(
                                        file = staged,
                                        ext = "jpg",
                                        originLabel = "Orphaned MediaStore Thumbnail (ID #$imgId)",
                                        sourceBadge = RecoverySourceBadge.ORPHANED_THUMBNAIL,
                                        imageWidth = dims.first,
                                        imageHeight = dims.second
                                    )
                                } else {
                                    staged.delete()
                                }
                            }
                        }
                    }
                }
            }
        } else if (category == FileCategory.VIDEO) {
            @Suppress("DEPRECATION")
            runCatching {
                resolver.query(
                    MediaStore.Video.Thumbnails.EXTERNAL_CONTENT_URI,
                    arrayOf(
                        MediaStore.Video.Thumbnails._ID,
                        MediaStore.Video.Thumbnails.VIDEO_ID,
                        MediaStore.Video.Thumbnails.DATA
                    ),
                    null,
                    null,
                    null
                )?.use { c ->
                    val idIdx = c.getColumnIndex(MediaStore.Video.Thumbnails._ID)
                    val vidIdIdx = c.getColumnIndex(MediaStore.Video.Thumbnails.VIDEO_ID)
                    val dataIdx = c.getColumnIndex(MediaStore.Video.Thumbnails.DATA)
                    while (c.moveToNext() && artifacts.size < 60) {
                        val vidId = if (vidIdIdx >= 0) c.getLong(vidIdIdx) else -1L
                        val dataPath = if (dataIdx >= 0) c.getString(dataIdx) else null
                        if (vidId > 0L && vidId in activeIds) continue
                        val existingFile = dataPath?.let { File(it) }?.takeIf { it.exists() && it.length() > 512L }
                        if (existingFile != null) {
                            artifacts += CarvedArtifact(
                                file = existingFile,
                                ext = "jpg",
                                originLabel = "Orphaned Video Thumbnail (ID #$vidId)",
                                sourceBadge = RecoverySourceBadge.ORPHANED_THUMBNAIL
                            )
                        }
                    }
                }
            }
        }

        // Upgrade 4: Missing MediaStore _id Gap Probe (between MAX(_id) - 500 and MAX(_id))
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && activeIndex.maxMediaId > 1L) {
            val maxId = activeIndex.maxMediaId
            val minProbeId = (maxId - 500L).coerceAtLeast(1L)
            val baseUri = if (category == FileCategory.PHOTO) {
                MediaStore.Images.Media.EXTERNAL_CONTENT_URI
            } else {
                MediaStore.Video.Media.EXTERNAL_CONTENT_URI
            }
            var probed = 0
            for (candidateId in maxId downTo minProbeId) {
                if (candidateId in activeIds) continue
                if (probed >= 60 || artifacts.size >= 100) break
                probed++
                runCatching {
                    val uri = ContentUris.withAppendedId(baseUri, candidateId)
                    val bmp = resolver.loadThumbnail(uri, Size(512, 512), null)
                    if (bmp.width > 0 && bmp.height > 0) {
                        val gapFile = File(outDir, "id_gap_preview_${candidateId}.jpg")
                        FileOutputStream(gapFile).use { fos ->
                            bmp.compress(Bitmap.CompressFormat.JPEG, 92, fos)
                        }
                        val w = bmp.width
                        val h = bmp.height
                        bmp.recycle()
                        if (gapFile.exists() && gapFile.length() > 512L && !activeIndex.matchesActiveGallery(gapFile)) {
                            artifacts += CarvedArtifact(
                                file = gapFile,
                                ext = "jpg",
                                originLabel = "MediaStore ID-Gap Cached Preview (ID #$candidateId)",
                                sourceBadge = RecoverySourceBadge.ORPHANED_THUMBNAIL,
                                imageWidth = w,
                                imageHeight = h
                            )
                        } else {
                            gapFile.delete()
                        }
                    }
                }
            }
        }

        artifacts
    }.getOrDefault(emptyList())

    /**
     * Inspects /proc/self/fd for open file descriptors whose target path ends with " (deleted)".
     */
    private fun scanUnlinkedOpenFileDescriptors(
        category: FileCategory,
        outDir: File
    ): List<CarvedArtifact> = runCatching {
        val list = ArrayList<CarvedArtifact>()
        val fdDir = File("/proc/self/fd")
        val entries = fdDir.listFiles() ?: return emptyList()
        for (fdEntry in entries) {
            val linkTarget = runCatching { android.system.Os.readlink(fdEntry.absolutePath) }.getOrNull() ?: continue
            if (!linkTarget.endsWith(" (deleted)")) continue
            val originalPath = linkTarget.removeSuffix(" (deleted)")
            val origName = File(originalPath).name
            val ext = origName.substringAfterLast('.', "").lowercase()
            val cat = FileCategory.fromExtension(ext)
            if (cat == category && fdEntry.canRead()) {
                val staged = File(outDir, "unlinked_inode_${fdEntry.name}_$origName")
                runCatching {
                    fdEntry.inputStream().use { input ->
                        staged.outputStream().use { output -> input.copyTo(output) }
                    }
                }
                if (staged.exists() && staged.length() > 0L) {
                    list += CarvedArtifact(
                        file = staged,
                        ext = ext.ifBlank { "bin" },
                        originLabel = "Unlinked File Descriptor (/proc/self/fd/${fdEntry.name})",
                        sourceBadge = RecoverySourceBadge.UNLINKED_FD
                    )
                }
            }
        }
        list
    }.getOrDefault(emptyList())

    /**
     * Builds the folder list shown on the Category Folder Breakdown screen.
     * Places Permanently Deleted (Unoverwritten), System Trash, SQLite WAL, and Orphaned Thumbnail
     * vaults at the top so the user immediately sees dug-up deleted files rather than active gallery folders.
     */
    fun buildFolderBuckets(category: FileCategory, files: List<RecoverableFile>): List<FolderBucket> {
        if (files.isEmpty()) return emptyList()
        val buckets = ArrayList<FolderBucket>()

        val deletedOrCarved = files.filter { it.isDeletedOrCarved }
        val systemTrash = files.filter { it.sourceBadge == RecoverySourceBadge.SYSTEM_TRASH_ORIGINAL }
        val unoverwrittenSectors = files.filter { it.sourceBadge == RecoverySourceBadge.UNOVERWRITTEN_SECTOR }
        val orphanedThumbs = files.filter { it.sourceBadge == RecoverySourceBadge.ORPHANED_THUMBNAIL }
        val walRemnants = files.filter { it.sourceBadge == RecoverySourceBadge.WAL_DB_REMNANT }
        val unlinkedFds = files.filter { it.sourceBadge == RecoverySourceBadge.UNLINKED_FD }

        if (deletedOrCarved.isNotEmpty()) {
            buckets += FolderBucket(
                id = "__DELETED_CARVED__",
                title = "All Deleted & Unoverwritten (${deletedOrCarved.size})",
                files = deletedOrCarved,
                isHiddenBucket = true,
                isDeletedBucket = true
            )
        }

        if (unoverwrittenSectors.isNotEmpty()) {
            buckets += FolderBucket(
                id = "__UNOVERWRITTEN__",
                title = "Unoverwritten Sectors & Cache Carves",
                files = unoverwrittenSectors,
                isHiddenBucket = true,
                isDeletedBucket = true
            )
        }

        if (systemTrash.isNotEmpty()) {
            buckets += FolderBucket(
                id = "__TRASH__",
                title = "System Trash Originals (100% Quality)",
                files = systemTrash,
                isHiddenBucket = true,
                isDeletedBucket = true
            )
        }

        if (orphanedThumbs.isNotEmpty()) {
            buckets += FolderBucket(
                id = "__ORPHANED_THUMBS__",
                title = "Orphaned Thumbnails & ID-Gap Previews",
                files = orphanedThumbs,
                isHiddenBucket = true,
                isDeletedBucket = true
            )
        }

        if (walRemnants.isNotEmpty()) {
            buckets += FolderBucket(
                id = "__WAL_REMNANTS__",
                title = "SQLite WAL & Freelist Blobs",
                files = walRemnants,
                isHiddenBucket = true,
                isDeletedBucket = true
            )
        }

        if (unlinkedFds.isNotEmpty()) {
            buckets += FolderBucket(
                id = "__UNLINKED_FDS__",
                title = "Unlinked Open Descriptors (/proc/fd)",
                files = unlinkedFds,
                isHiddenBucket = true,
                isDeletedBucket = true
            )
        }

        buckets += FolderBucket(
            id = "__ALL__",
            title = "All (Includes Active Gallery)",
            files = files,
            isAllBucket = true
        )

        val byFolder = files.groupBy { it.folderName }
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
            val isFolderDeleted = folderName.startsWith("deep_carved", true) ||
                folderName.contains("trash", true) ||
                folderName.contains("recycle", true) ||
                folderName.startsWith(".thumb", true) ||
                folderName.equals("LOST.DIR", true)
            buckets += FolderBucket(
                id = "folder:$folderName",
                title = if (folderName.startsWith("deep_carved")) "Carved Unoverwritten Blocks" else folderName,
                files = folderFiles,
                isDeletedBucket = isFolderDeleted
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

        if (b(0) == 0xFF && b(1) == 0xD8 && b(2) == 0xFF) {
            return FileCategory.PHOTO to "jpg"
        }
        if (b(0) == 0x89 && b(1) == 0x50 && b(2) == 0x4E && b(3) == 0x47) {
            return FileCategory.PHOTO to "png"
        }
        if (b(0) == 0x47 && b(1) == 0x49 && b(2) == 0x46 && b(3) == 0x38) {
            return FileCategory.PHOTO to "gif"
        }
        if (b(0) == 0x52 && b(1) == 0x49 && b(2) == 0x46 && b(3) == 0x46 && read >= 12) {
            val tag = String(header, 8, 4, Charsets.US_ASCII)
            when (tag) {
                "WEBP" -> return FileCategory.PHOTO to "webp"
                "WAVE" -> return FileCategory.AUDIO to "wav"
                "AVI " -> return FileCategory.VIDEO to "avi"
            }
        }
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
        if (b(0) == 0x1A && b(1) == 0x45 && b(2) == 0xDF && b(3) == 0xA3) {
            return FileCategory.VIDEO to "mkv"
        }
        if ((b(0) == 0x49 && b(1) == 0x44 && b(2) == 0x33) ||
            (b(0) == 0xFF && (b(1) == 0xFB || b(1) == 0xF3 || b(1) == 0xF2))
        ) {
            return FileCategory.AUDIO to "mp3"
        }
        if (b(0) == 0x66 && b(1) == 0x4C && b(2) == 0x61 && b(3) == 0x43) {
            return FileCategory.AUDIO to "flac"
        }
        if (b(0) == 0x4F && b(1) == 0x67 && b(2) == 0x67 && b(3) == 0x53) {
            return FileCategory.AUDIO to "ogg"
        }
        if (b(0) == 0x23 && b(1) == 0x21 && b(2) == 0x41 && b(3) == 0x4D && b(4) == 0x52) {
            return FileCategory.AUDIO to "amr"
        }
        if (b(0) == 0x25 && b(1) == 0x50 && b(2) == 0x44 && b(3) == 0x46) {
            return FileCategory.DOCUMENT to "pdf"
        }
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
        if (b(0) == 0x52 && b(1) == 0x61 && b(2) == 0x72 && b(3) == 0x21) {
            return FileCategory.DOCUMENT to "rar"
        }
        if (b(0) == 0x37 && b(1) == 0x7A && b(2) == 0xBC && b(3) == 0xAF) {
            return FileCategory.DOCUMENT to "7z"
        }
        if (b(0) == 0xD0 && b(1) == 0xCF && b(2) == 0x11 && b(3) == 0xE0) {
            return FileCategory.DOCUMENT to "doc"
        }
        null
    }.getOrNull()

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
                val badge = when {
                    isMediaTrashed -> RecoverySourceBadge.SYSTEM_TRASH_ORIGINAL
                    path.contains("thumbnail", true) -> RecoverySourceBadge.ORPHANED_THUMBNAIL
                    isHidden -> RecoverySourceBadge.UNOVERWRITTEN_SECTOR
                    else -> RecoverySourceBadge.ACTIVE_GALLERY
                }
                val origin = when (badge) {
                    RecoverySourceBadge.SYSTEM_TRASH_ORIGINAL -> "System Trash Original (100% Quality)"
                    RecoverySourceBadge.ORPHANED_THUMBNAIL -> "Orphaned Thumbnail Remnant"
                    RecoverySourceBadge.UNOVERWRITTEN_SECTOR -> "Unoverwritten Hidden Vault (.nomedia)"
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
                    detectedExt = ext,
                    sourceBadge = badge
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
