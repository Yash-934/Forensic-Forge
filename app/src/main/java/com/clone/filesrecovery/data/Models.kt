package com.clone.filesrecovery.data

import java.io.File
import java.text.DecimalFormat
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.log10
import kotlin.math.pow

/**
 * Forensic source badge categories for recovered & carved artifacts.
 */
enum class RecoverySourceBadge(
    val id: String,
    val displayBadge: String,
    val description: String
) {
    UNOVERWRITTEN_SECTOR(
        id = "UNOVERWRITTEN_SECTOR",
        displayBadge = "UNOVERWRITTEN_SECTOR",
        description = "Carved from unoverwritten disk sectors, .thumbdata blobs, .exo/.cnt caches, or LOST.DIR clusters"
    ),
    SYSTEM_TRASH_ORIGINAL(
        id = "SYSTEM_TRASH_ORIGINAL",
        displayBadge = "SYSTEM_TRASH_ORIGINAL",
        description = "100% original quality file from Android System Trash (IS_TRASHED/IS_PENDING) or OEM Recycle Bin"
    ),
    ORPHANED_THUMBNAIL(
        id = "ORPHANED_THUMBNAIL",
        displayBadge = "ORPHANED_THUMBNAIL",
        description = "Orphaned thumbnail or MediaStore ID-gap preview whose original gallery item was permanently deleted"
    ),
    WAL_DB_REMNANT(
        id = "WAL_DB_REMNANT",
        displayBadge = "WAL_DB_REMNANT",
        description = "Carved from unoverwritten 4 KB SQLite WAL frames, journal pages, or database freelist blocks"
    ),
    UNLINKED_FD(
        id = "UNLINKED_FD",
        displayBadge = "UNLINKED_FD",
        description = "Recovered from an unlinked open file descriptor (/proc/*/fd/* -> deleted) before block reclamation"
    ),
    ACTIVE_GALLERY(
        id = "ACTIVE_GALLERY",
        displayBadge = "GALLERY",
        description = "Active non-deleted file currently indexed in standard device storage"
    )
}

/**
 * Stream integrity status for carved media containers (e.g., ISO BMFF MP4/MOV atom chains).
 */
enum class StreamIntegrityStatus(val label: String) {
    INTACT("INTACT_STREAM"),
    NEEDS_REPAIR_PARTIAL("NEEDS_REPAIR / PARTIAL_STREAM")
}

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
    val detectedExt: String = "",
    val sourceBadge: RecoverySourceBadge = inferSourceBadge(recoveryOrigin, name, isHiddenOrTrashed),
    val streamIntegrity: StreamIntegrityStatus = StreamIntegrityStatus.INTACT,
    val imageWidth: Int = 0,
    val imageHeight: Int = 0
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

    val isDeletedOrCarved: Boolean
        get() = sourceBadge != RecoverySourceBadge.ACTIVE_GALLERY ||
            isHiddenOrTrashed ||
            recoveryOrigin.contains("Unoverwritten", ignoreCase = true) ||
            recoveryOrigin.contains("Carved", ignoreCase = true) ||
            recoveryOrigin.contains("Trash", ignoreCase = true) ||
            recoveryOrigin.contains("Recycle", ignoreCase = true) ||
            recoveryOrigin.contains("Thumbnail", ignoreCase = true) ||
            recoveryOrigin.contains("Cache", ignoreCase = true) ||
            recoveryOrigin.contains("Hidden", ignoreCase = true) ||
            recoveryOrigin.contains("Signature", ignoreCase = true) ||
            recoveryOrigin.contains("Orphan", ignoreCase = true) ||
            recoveryOrigin.contains("Unlinked", ignoreCase = true) ||
            recoveryOrigin.contains("WAL", ignoreCase = true) ||
            recoveryOrigin.contains("LOST.DIR", ignoreCase = true)

    val needsRepairPartialStream: Boolean
        get() = streamIntegrity == StreamIntegrityStatus.NEEDS_REPAIR_PARTIAL ||
            recoveryOrigin.contains("NEEDS_REPAIR", ignoreCase = true) ||
            recoveryOrigin.contains("PARTIAL_STREAM", ignoreCase = true)

    val recoveryBadgeLabel: String
        get() = sourceBadge.displayBadge

    companion object {
        fun inferSourceBadge(
            origin: String,
            fileName: String,
            isHiddenOrTrashed: Boolean
        ): RecoverySourceBadge = when {
            origin.contains("UNLINKED_FD", true) ||
                origin.contains("Unlinked", true) -> RecoverySourceBadge.UNLINKED_FD
            origin.contains("WAL_DB_REMNANT", true) ||
                origin.contains("WAL", true) ||
                origin.contains("SQLite", true) ||
                origin.contains("Freelist", true) -> RecoverySourceBadge.WAL_DB_REMNANT
            origin.contains("SYSTEM_TRASH_ORIGINAL", true) ||
                origin.contains("Trash", true) ||
                origin.contains("Recycle", true) ||
                fileName.contains(".trashed", true) -> RecoverySourceBadge.SYSTEM_TRASH_ORIGINAL
            origin.contains("ORPHANED_THUMBNAIL", true) ||
                origin.contains("Orphaned", true) ||
                origin.contains("ID-Gap", true) ||
                origin.contains("Thumbnail", true) -> RecoverySourceBadge.ORPHANED_THUMBNAIL
            origin.contains("UNOVERWRITTEN_SECTOR", true) ||
                origin.contains("Unoverwritten", true) ||
                origin.contains("Carved", true) ||
                origin.contains("Signature", true) ||
                origin.contains("LOST.DIR", true) ||
                origin.contains("Cache", true) ||
                isHiddenOrTrashed -> RecoverySourceBadge.UNOVERWRITTEN_SECTOR
            else -> RecoverySourceBadge.ACTIVE_GALLERY
        }
    }
}

data class FolderBucket(
    val id: String,
    val title: String,
    val files: List<RecoverableFile>,
    val isHiddenBucket: Boolean = false,
    val isAllBucket: Boolean = false,
    val isDeletedBucket: Boolean = false
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
