package com.clone.filesrecovery.data

import java.io.File
import java.text.DecimalFormat
import java.util.Date
import kotlin.math.log10
import kotlin.math.pow

/**
 * File categories with their extension rules.
 * In the original app each type has its own "rule check" class
 * (ImageFileRuleCheck / VideoFileRuleCheck / AudioFileRuleCheck / DocumentFileRuleCheck);
 * here the same idea is expressed as one enum.
 */
enum class FileCategory(
    val title: String,
    val subtitle: String,
    val extensions: Set<String>
) {
    PHOTO("Photos", "Recover deleted photos", setOf("jpg", "jpeg", "png", "gif", "webp", "bmp", "heic", "heif", "avif", "dng")),
    VIDEO("Videos", "Recover deleted videos", setOf("mp4", "mkv", "avi", "mov", "webm", "3gp", "m4v", "wmv", "flv")),
    AUDIO("Audios", "Recover deleted audios", setOf("mp3", "wav", "aac", "m4a", "ogg", "flac", "opus", "amr", "awb")),
    DOCUMENT("Documents", "Recover deleted documents", setOf("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "odt", "csv", "zip", "rar", "7z"));

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
    val lastModified: Long
) {
    val folderName: String get() = File(path).parentFile?.name ?: "Storage"
    val extension: String get() = name.substringAfterLast('.', "").lowercase()
}

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
    /** true = media/transport notification, false = message/other (original app has Media | Message tabs) */
    val isMedia: Boolean
)

data class ContactInfo(
    val id: String,
    val name: String,
    val phones: List<String>,
    val emails: List<String>
)

fun formatSize(bytes: Long): String {
    if (bytes <= 0) return "0 B"
    val units = arrayOf("B", "KB", "MB", "GB", "TB")
    val digitGroups = (log10(bytes.toDouble()) / log10(1024.0)).toInt().coerceIn(0, units.lastIndex)
    return DecimalFormat("#,##0.#").format(bytes / 1024.0.pow(digitGroups.toDouble())) + " " + units[digitGroups]
}

fun formatDate(time: Long): String =
    android.text.format.DateFormat.format("dd MMM yyyy, hh:mm a", Date(time)).toString()
