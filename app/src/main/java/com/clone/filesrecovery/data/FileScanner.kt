package com.clone.filesrecovery.data

import android.content.ContentValues
import android.content.Context
import android.media.MediaMetadataRetriever
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Recovery scan engine.
 *
 * Android cannot truly "undelete" sectors without root, so — exactly like the
 * original app and every Play-Store recovery app — the scan walks the shared
 * storage (after the user grants All Files Access) and collects media/document
 * files that are still physically present but usually "lost" for the user:
 * hidden files, files in app folders, .nomedia folders, messaging-app caches,
 * trash folders, thumbnails' full-size partners, etc. Recover = copy them into
 * a visible public folder (Downloads/FilesRecovery).
 */
object FileScanner {

    private val SKIP_DIRS = setOf("Android/data", "Android/obb")
    private const val MAX_DEPTH = 14

    suspend fun scan(
        context: Context,
        category: FileCategory,
        onProgress: (scanned: Int, currentPath: String) -> Unit
    ): List<RecoverableFile> = withContext(Dispatchers.IO) {
        val root = Environment.getExternalStorageDirectory()
        val results = ArrayList<RecoverableFile>()
        var scanned = 0
        if (root != null && root.exists()) {
            root.walkTopDown()
                .maxDepth(MAX_DEPTH)
                .onEnter { dir ->
                    val rel = dir.relativeTo(root).path.replace('\\', '/')
                    SKIP_DIRS.none { rel == it || rel.startsWith("$it/") }
                }
                .forEach { f ->
                    if (f.isFile) {
                        scanned++
                        if (scanned % 40 == 0) onProgress(scanned, f.path)
                        val cat = FileCategory.fromExtension(f.extension) ?: return@forEach
                        if (cat == category && f.length() > 0) {
                            results += RecoverableFile(
                                path = f.absolutePath,
                                name = f.name,
                                category = cat,
                                size = f.length(),
                                lastModified = f.lastModified()
                            )
                        }
                    }
                }
        }
        onProgress(scanned, "")
        results.sortedByDescending { it.lastModified }
    }

    /** Copy selected files into the public FilesRecovery folder and record history. */
    suspend fun recover(context: Context, files: List<RecoverableFile>): List<RecoveredRecord> =
        withContext(Dispatchers.IO) {
            val done = ArrayList<RecoveredRecord>()
            for (item in files) {
                val src = File(item.path)
                if (!src.exists()) continue
                val savedPath = copyToPublicFolder(context, src, item.category)
                if (savedPath != null) {
                    done += RecoveredRecord(
                        originalPath = item.path,
                        recoveredPath = savedPath,
                        name = item.name,
                        category = item.category,
                        size = item.size,
                        recoveredAt = System.currentTimeMillis()
                    )
                }
            }
            if (done.isNotEmpty()) AppStore.addRecovered(context, done)
            done
        }

    private fun copyToPublicFolder(context: Context, src: File, category: FileCategory): String? {
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
                put(MediaStore.MediaColumns.DISPLAY_NAME, uniqueName(context, collection, src.name))
                put(MediaStore.MediaColumns.RELATIVE_PATH, relativePath)
                put(MediaStore.MediaColumns.IS_PENDING, 1)
            }
            val resolver = context.contentResolver
            var uri: Uri? = null
            runCatching {
                uri = resolver.insert(collection, values)
                uri?.let { u ->
                    resolver.openOutputStream(u)?.use { out -> src.inputStream().use { it.copyTo(out) } }
                    values.clear()
                    values.put(MediaStore.MediaColumns.IS_PENDING, 0)
                    resolver.update(u, values, null, null)
                }
            }.onFailure { uri?.let { runCatching { resolver.delete(it, null, null) } }; return null }
            uri?.let { relativePath + "/" + src.name }
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
            val dest = File(dir, src.name).let { if (it.exists()) File(dir, "${System.currentTimeMillis()}_${src.name}") else it }
            runCatching { src.inputStream().use { i -> dest.outputStream().use { o -> i.copyTo(o) } }; dest.absolutePath }.getOrNull()
        }
    }

    private fun uniqueName(context: Context, collection: Uri, name: String): String {
        // MediaStore renames duplicates automatically on most devices; keep the name as-is.
        return name
    }

    fun videoDurationMs(path: String): Long = runCatching {
        val r = MediaMetadataRetriever()
        r.setDataSource(path)
        val v = r.extractMetadata(MediaMetadataRetriever.METADATA_KEY_DURATION)?.toLongOrNull() ?: 0L
        r.release()
        v
    }.getOrDefault(0L)
}
