package com.clone.filesrecovery.forensics

import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Core data models for DeepVault's deterministic, offline Forensic Analysis &
 * AI-Ready Report Engine (Schema v1.0).
 *
 * Strictly offline and deterministic: no AI/LLM SDK or external network calls.
 */
object ForensicConstants {
    const val SCHEMA_VERSION = "1.0"
    const val APP_NAME = "DeepVault"
    const val APP_VERSION = "2.0.0"
    const val PARSER_SUITE_VERSION = "DeepVault-BinaryParser/2.0 (Android ExifInterface 1.3.7; Java Zip/PDF/RIFF/ISOBMFF)"
}

/**
 * Generates stable, deterministic Evidence IDs (e.g. DV-000001) across reports
 * for a given file key within a case/session.
 */
object EvidenceIdRegistry {
    private val counter = AtomicInteger(0)
    private val keyToId = ConcurrentHashMap<String, String>()

    @Synchronized
    fun getOrAssign(path: String, sizeBytes: Long): String {
        val normalizedKey = "${path.trim()}|$sizeBytes"
        return keyToId.getOrPut(normalizedKey) {
            val next = counter.incrementAndGet()
            String.format(Locale.US, "DV-%06d", next)
        }
    }

    @Synchronized
    fun resetForTest() {
        counter.set(0)
        keyToId.clear()
    }
}

enum class ExportFormat(val label: String, val extension: String, val mimeType: String) {
    JSON("JSON", "json", "application/json"),
    MARKDOWN("Markdown", "md", "text/markdown"),
    PDF("PDF", "pdf", "application/pdf"),
    CSV("CSV", "csv", "text/csv"),
    EXTERNAL_AI_BUNDLE("External AI Bundle", "bundle", "*/*")
}

data class MetadataField(
    val key: String,
    val value: String,
    val source: String, // e.g. "embedded_exif", "filesystem_stat", "binary_header", "container_metadata", "pdf_dictionary", "zip_central_directory"
    val valueCategory: String = "observed" // "observed", "embedded", "filesystem", "application_recorded"
)

data class GpsCoordinates(
    val latitude: Double,
    val longitude: Double,
    val altitudeMeters: Double? = null,
    val gpsTimestampUtc: String? = null,
    val gpsProcessingMethod: String? = null,
    val source: String = "embedded_exif"
)

data class ImageForensicMetadata(
    val width: Int? = null,
    val height: Int? = null,
    val detectedFormat: String? = null,
    val colorProfileOrConfig: String? = null,
    val cameraMake: String? = null,
    val cameraModel: String? = null,
    val captureTimestampRaw: String? = null,
    val subSecTimeOriginal: String? = null,
    val orientation: String? = null,
    val software: String? = null,
    val gps: GpsCoordinates? = null,
    val hasEmbeddedThumbnail: Boolean = false,
    val thumbnailWidth: Int? = null,
    val thumbnailHeight: Int? = null,
    val compressionInfo: String? = null,
    val exposureTime: String? = null,
    val fNumber: String? = null,
    val isoSpeed: String? = null,
    val focalLength: String? = null,
    val filesystemLastModifiedIso: String? = null
)

data class VideoForensicMetadata(
    val containerFormat: String? = null,
    val majorBrand: String? = null,
    val videoCodec: String? = null,
    val audioCodec: String? = null,
    val width: Int? = null,
    val height: Int? = null,
    val durationMs: Long? = null,
    val frameRateFps: String? = null,
    val bitrateBps: Long? = null,
    val rotationDegrees: Int? = null,
    val trackCount: Int? = null,
    val embeddedCreationTimestampRaw: String? = null,
    val filesystemLastModifiedIso: String? = null,
    val structuralAtomsFound: List<String> = emptyList()
)

data class AudioForensicMetadata(
    val format: String? = null,
    val codecOrMime: String? = null,
    val durationMs: Long? = null,
    val sampleRateHz: Int? = null,
    val channelCount: Int? = null,
    val bitrateBps: Long? = null,
    val titleTag: String? = null,
    val artistTag: String? = null,
    val albumTag: String? = null,
    val yearTag: String? = null,
    val genreTag: String? = null,
    val tagContainerType: String? = null,
    val filesystemLastModifiedIso: String? = null
)

data class DocumentArchiveForensicMetadata(
    val formatType: String? = null,
    val author: String? = null,
    val creatorOrLastModifiedBy: String? = null,
    val producerOrApplication: String? = null,
    val title: String? = null,
    val creationDateRaw: String? = null,
    val modificationDateRaw: String? = null,
    val pageCount: Int? = null,
    val archiveEntryCount: Int? = null,
    val archiveEntriesSample: List<String> = emptyList(),
    val embeddedAttachments: List<String> = emptyList(),
    val structureSummary: String? = null,
    val digitalSignatureStatus: String = "not_present" // "present_unverified_chain", "not_present", "not_applicable"
)

data class ForensicTimelineEvent(
    val evidenceId: String,
    val eventType: String, // e.g., "filesystem_last_modified", "exif_datetime_original", "pdf_creation_date", "recovery_event"
    val timestampRaw: String,
    val timestampIso: String?,
    val timezoneStatus: String, // "explicit_utc", "explicit_offset", "local_unverified"
    val source: String,
    val notes: String = ""
)

data class ForensicFinding(
    val findingId: String,
    val evidenceId: String,
    val severity: String, // "info", "notice", "warning", "high"
    val category: String, // "signature_validation", "extension_mismatch", "structure_validation", "metadata_consistency", "duplicate_detection", "recovery_completeness"
    val title: String,
    val description: String,
    val observationBasis: String // "rule_based_finding", "direct_observation", "inference"
)

data class ForensicEvidenceRecord(
    val evidenceId: String,
    val originalFilename: String?,
    val currentFilename: String,
    val sizeBytes: Long,
    val extension: String,
    val detectedMimeType: String,
    val detectedFormat: String,
    val signatureHex: String,
    val magicDescription: String,
    val sourceLocation: String?,
    val recoveredOutputPath: String?,
    val recoveryStatus: String, // "recovered", "carved_candidate", "accessible_active", "unreadable"
    val recoveryMethod: String, // "filesystem_traversal", "magic_byte_carving", "mediastore_trashed_query", "thumbdata_jpeg_stream_carve", "direct_inspection"
    val recoveryTimestampIso: String?,
    val scanSessionId: String,
    val completenessStatus: String, // "complete", "partial", "unverified"
    val structureCheck: String, // "passed", "warning", "corrupted", "not_tested"
    val structureDetail: String,
    val signatureCheck: String, // "passed", "mismatch", "unknown_signature", "empty_file"
    val extensionMismatch: Boolean,
    val extensionMismatchDetail: String?,
    val corruptionIndicators: List<String>,
    val sha256: String,
    val md5: String?,
    val sha1: String?,
    val hashCalculatedAtIso: String,
    val hashTarget: String, // "recovered_output" or "acquired_source"
    val referenceHash: String? = null,
    val referenceHashMatch: String = "not_applicable", // "matched", "mismatched", "not_applicable"
    val metadataSourceSummary: String,
    val extractedFields: List<MetadataField>,
    val unavailableFields: List<String>,
    val parserWarnings: List<String>,
    val metadataInconsistencies: List<String>,
    val imageMetadata: ImageForensicMetadata? = null,
    val videoMetadata: VideoForensicMetadata? = null,
    val audioMetadata: AudioForensicMetadata? = null,
    val documentMetadata: DocumentArchiveForensicMetadata? = null,
    val timeline: List<ForensicTimelineEvent>,
    val findings: List<ForensicFinding>,
    val limitations: List<String>,
    val errors: List<String>,
    val duplicateGroupId: String? = null,
    val similarFileEvidenceIds: List<String> = emptyList(),
    val isRedacted: Boolean = false,
    val redactedFieldNames: List<String> = emptyList()
)

data class ForensicPrivacyOptions(
    val includeGps: Boolean = true,
    val redactSensitivePaths: Boolean = false,
    val excludePersonalFilenames: Boolean = false,
    val excludePersonalMetadata: Boolean = false,
    val excludeNotes: Boolean = false,
    val excludedEvidenceIds: Set<String> = emptySet(),
    val maxEvidencePerReportPart: Int = 50
) {
    val isSanitized: Boolean
        get() = !includeGps || redactSensitivePaths || excludePersonalFilenames ||
            excludePersonalMetadata || excludeNotes || excludedEvidenceIds.isNotEmpty()

    fun buildRedactionSummary(): List<String> {
        val list = mutableListOf<String>()
        if (!includeGps) list.add("gps_coordinates_excluded")
        if (redactSensitivePaths) list.add("sensitive_filesystem_paths_redacted")
        if (excludePersonalFilenames) list.add("personal_filenames_redacted")
        if (excludePersonalMetadata) list.add("personal_author_owner_metadata_excluded")
        if (excludeNotes) list.add("analyst_notes_excluded")
        if (excludedEvidenceIds.isNotEmpty()) list.add("selected_evidence_items_excluded(${excludedEvidenceIds.size})")
        return list
    }
}

data class DeviceForensicInfo(
    val manufacturer: String,
    val model: String,
    val androidRelease: String,
    val sdkInt: Int,
    val deviceBoardOrHardware: String,
    val storageAccessMode: String,
    val parserSuiteVersion: String = ForensicConstants.PARSER_SUITE_VERSION
)

data class HashManifestEntry(
    val evidenceId: String,
    val filename: String,
    val sizeBytes: Long,
    val sha256: String,
    val md5: String?,
    val sha1: String?,
    val hashTarget: String,
    val calculatedAtIso: String
)

data class DuplicateEvidenceGroup(
    val groupId: String,
    val matchBasis: String, // "exact_sha256" or "perceptual_dhash"
    val hashValue: String,
    val evidenceIds: List<String>,
    val filenames: List<String>,
    val totalBytes: Long
)

data class RecoveryStatistics(
    val totalFilesEvaluated: Int,
    val recoveredCompleteCount: Int,
    val partialOrCarvedCount: Int,
    val corruptedOrWarningCount: Int,
    val extensionMismatchCount: Int,
    val duplicateGroupCount: Int,
    val totalBytesAnalyzed: Long,
    val byFormatCounts: Map<String, Int>
)

data class ForensicCaseReport(
    val reportId: String,
    val reportVersion: Int = 1,
    val schemaVersion: String = ForensicConstants.SCHEMA_VERSION,
    val reportType: String, // "individual_file" or "combined_case"
    val generatedAtIso: String,
    val appName: String = ForensicConstants.APP_NAME,
    val appVersion: String = ForensicConstants.APP_VERSION,
    val caseId: String,
    val caseCreatedAtIso: String,
    val scanSessionId: String,
    val deviceInfo: DeviceForensicInfo,
    val acquisitionMethod: String,
    val privacyOptions: ForensicPrivacyOptions,
    val isSanitized: Boolean,
    val redactionSummary: List<String>,
    val evidenceItems: List<ForensicEvidenceRecord>,
    val hashManifest: List<HashManifestEntry>,
    val recoveryStats: RecoveryStatistics,
    val timeline: List<ForensicTimelineEvent>,
    val duplicateGroups: List<DuplicateEvidenceGroup>,
    val findings: List<ForensicFinding>,
    val limitations: List<String>,
    val errors: List<String>,
    val partNumber: Int = 1,
    val totalParts: Int = 1,
    val totalEvidenceInCase: Int = evidenceItems.size
)

data class ExportedReportFile(
    val role: String, // "json_report", "markdown_report", "pdf_report", "csv_metadata", "csv_timeline", "csv_inventory", "case_summary", "ai_analysis_brief", "sha256_manifest"
    val format: String,
    val file: File,
    val sha256: String,
    val sizeBytes: Long,
    val partNumber: Int = 1,
    val totalParts: Int = 1
)

data class ExportedReportBundle(
    val reportId: String,
    val reportVersion: Int,
    val caseId: String,
    val generatedAtIso: String,
    val isSanitized: Boolean,
    val redactedFields: List<String>,
    val files: List<ExportedReportFile>,
    val manifestFile: File,
    val includedEvidenceIds: List<String>
)

data class FileHashCheckResult(
    val filename: String,
    val role: String,
    val expectedSha256: String,
    val actualSha256: String?,
    val fileExists: Boolean,
    val passed: Boolean
)

data class ReportVerificationResult(
    val reportId: String,
    val verifiedAtIso: String,
    val allPassed: Boolean,
    val fileResults: List<FileHashCheckResult>,
    val summaryMessage: String,
    val disclaimer: String = "A report hash proves the byte-level integrity of the exported report files being compared; it does not independently prove the accuracy of the underlying forensic conclusions."
)

object ForensicTimeUtil {
    fun nowIsoUtc(): String {
        val sdf = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
        sdf.timeZone = TimeZone.getTimeZone("UTC")
        return sdf.format(Date())
    }

    fun epochMillisToIsoUtc(epochMillis: Long): String? {
        if (epochMillis <= 0L) return null
        val sdf = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
        sdf.timeZone = TimeZone.getTimeZone("UTC")
        return sdf.format(Date(epochMillis))
    }

    /**
     * Parses EXIF local timestamp ("yyyy:MM:dd HH:mm:ss") without silently claiming it is UTC,
     * unless an explicit offset tag is provided.
     */
    fun parseExifTimestamp(raw: String?, offsetTag: String? = null): Pair<String?, String> {
        if (raw.isNullOrBlank()) return null to "unavailable"
        val cleaned = raw.trim()
        // Format: 2026:10:20 14:30:05
        val regex = Regex("""^(\d{4}):(\d{2}):(\d{2})\s+(\d{2}):(\d{2}):(\d{2})$""")
        val m = regex.matchEntire(cleaned) ?: return cleaned to "local_unverified"
        val (y, mo, d, h, mi, s) = m.destructured
        return if (!offsetTag.isNullOrBlank() && (offsetTag.startsWith("+") || offsetTag.startsWith("-"))) {
            "$y-$mo-${d}T$h:$mi:$s$offsetTag" to "explicit_offset"
        } else {
            "$y-$mo-${d}T$h:$mi:$s (local_unverified_tz)" to "local_unverified"
        }
    }

    /**
     * Parses PDF date strings like "D:20261020143005Z" or "D:20261020143005+05'30'".
     */
    fun parsePdfTimestamp(raw: String?): Pair<String?, String> {
        if (raw.isNullOrBlank()) return null to "unavailable"
        val s = raw.trim().removePrefix("D:")
        if (s.length < 8) return raw.trim() to "local_unverified"
        val year = s.substring(0, 4)
        val month = s.substring(4, 6)
        val day = s.substring(6, 8)
        val hour = if (s.length >= 10) s.substring(8, 10) else "00"
        val min = if (s.length >= 12) s.substring(10, 12) else "00"
        val sec = if (s.length >= 14) s.substring(12, 14) else "00"
        val tail = if (s.length > 14) s.substring(14).replace("'", "") else ""
        return when {
            tail.startsWith("Z", ignoreCase = true) ->
                "$year-$month-${day}T$hour:$min:${sec}Z" to "explicit_utc"
            tail.startsWith("+") || tail.startsWith("-") ->
                "$year-$month-${day}T$hour:$min:$sec$tail" to "explicit_offset"
            else ->
                "$year-$month-${day}T$hour:$min:$sec (local_unverified_tz)" to "local_unverified"
        }
    }
}
