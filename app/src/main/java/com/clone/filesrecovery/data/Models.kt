package com.clone.filesrecovery.data

import java.io.File
import java.text.DecimalFormat
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.log10
import kotlin.math.pow

/**
 * File categories with comprehensive extension rules + magic-byte support.
 */
enum class FileCategory(
    val title: String,
    val recoveryTitle: String,
    val countableLabel: String,
    val subtitle: String,
    val extensions: Set<String>
) {
    PHOTO(
        title = "Photos",
        recoveryTitle = "Photo Recovery",
        countableLabel = "photos",
        subtitle = "Recover deleted photos",
        extensions = setOf(
            "jpg", "jpeg", "png", "gif", "webp", "bmp", "heic", "heif", "avif",
            "dng", "cr2", "nef", "arw", "raw", "svg", "ico", "tif", "tiff", "jfif"
        )
    ),
    VIDEO(
        title = "Videos",
        recoveryTitle = "Video Recovery",
        countableLabel = "videos",
        subtitle = "Recover deleted videos",
        extensions = setOf(
            "mp4", "mkv", "avi", "mov", "webm", "3gp", "3g2", "m4v", "wmv",
            "flv", "ts", "m2ts", "mts", "vob", "ogv", "mpg", "mpeg", "divx", "asf"
        )
    ),
    AUDIO(
        title = "Audios",
        recoveryTitle = "Audio Recovery",
        countableLabel = "audios",
        subtitle = "Recover deleted audios",
        extensions = setOf(
            "mp3", "wav", "aac", "m4a", "ogg", "flac", "opus", "amr", "awb",
            "wma", "mid", "midi", "aiff", "alac", "ape", "mka", "caf"
        )
    ),
    DOCUMENT(
        title = "Documents",
        recoveryTitle = "Document Recovery",
        countableLabel = "files",
        subtitle = "Recover deleted documents",
        extensions = setOf(
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf",
            "odt", "ods", "odp", "csv", "tsv", "zip", "rar", "7z", "tar", "gz",
            "bz2", "xz", "apk", "xapk", "apks", "epub", "mobi", "azw3", "json",
            "xml", "html", "htm", "md", "log", "ini", "cfg", "conf", "vcf",
            "ics", "db", "sqlite", "sql", "torrent", "psd", "ai"
        )
    );

    companion object {
        fun fromExtension(ext: String): FileCategory? =
            entries.firstOrNull { it.extensions.contains(ext.lowercase()) }
    }
}

data class RecoverableFile(
    val path: String,
    val name: String,
    val category: FileCategory,
    val size: Long,
    val lastModified: Long,
    val isHiddenOrTrashed: Boolean = false,
    val recoveryOrigin: String = "Storage",
    val detectedExt: String = ""
) {
    val folderName: String
        get() {
            val parent = File(path).parentFile ?: return "Storage"
            val n = parent.name
            return if (n.isBlank() || n == "emulated") "Storage" else n
        }

    val extension: String
        get() = detectedExt.ifBlank { name.substringAfterLast('.', "").lowercase() }

    val dateGroupKey: String
        get() = formatGroupDate(lastModified)
}

data class FolderBucket(
    val id: String,
    val title: String,
    val files: List<RecoverableFile>,
    val isHiddenBucket: Boolean = false,
    val isAllBucket: Boolean = false
)

data class StorageBreakdown(
    val totalBytes: Long = 0L,
    val usedBytes: Long = 0L,
    val photosBytes: Long = 0L,
    val videosBytes: Long = 0L,
    val documentsBytes: Long = 0L,
    val audiosBytes: Long = 0L,
    val othersBytes: Long = 0L
)

data class RecoveredRecord(
    val originalPath: String,
    val recoveredPath: String,
    val name: String,
    val category: FileCategory,
    val size: Long,
    val recoveredAt: Long
)

data class SavedNotification(
    val id: Long,
    val packageName: String,
    val appLabel: String,
    val title: String,
    val text: String,
    val time: Long,
    val isMedia: Boolean
)

data class ContactInfo(
    val id: String,
    val name: String,
    val phones: List<String>,
    val emails: List<String>,
    val isDeletedOrBackup: Boolean = false,
    val sourceLabel: String = "Device"
)

data class SimilarImageGroup(
    val id: String,
    val title: String,
    val files: List<RecoverableFile>
)

fun formatSize(bytes: Long): String {
    if (bytes <= 0) return "0B"
    val units = arrayOf("B", "KB", "MB", "GB", "TB")
    val digitGroups = (log10(bytes.toDouble()) / log10(1024.0)).toInt().coerceIn(0, units.lastIndex)
    return DecimalFormat("#,##0.##").format(bytes / 1024.0.pow(digitGroups.toDouble())) + units[digitGroups]
}

fun formatGbPair(usedBytes: Long, totalBytes: Long): Pair<String, String> {
    val gb = 1024.0 * 1024.0 * 1024.0
    val df = DecimalFormat("0.00")
    return "${df.format(usedBytes / gb)} GB" to " / ${df.format(totalBytes / gb)} GB"
}

fun formatDate(time: Long): String =
    android.text.format.DateFormat.format("dd MMM yyyy, hh:mm a", Date(time)).toString()

fun formatGroupDate(time: Long): String {
    val safeTime = if (time <= 0L) System.currentTimeMillis() else time
    return SimpleDateFormat("MMMM dd.yyyy", Locale.ENGLISH).format(Date(safeTime))
}

fun middleEllipsize(text: String, maxChars: Int = 30): String {
    if (text.length <= maxChars) return text
    val head = (maxChars - 1) / 2
    val tail = maxChars - 1 - head
    return text.take(head) + "…" + text.takeLast(tail)
}
