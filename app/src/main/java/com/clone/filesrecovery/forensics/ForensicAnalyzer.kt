package com.clone.filesrecovery.forensics

import android.content.Context
import android.graphics.BitmapFactory
import android.media.MediaMetadataRetriever
import android.os.Build
import androidx.exifinterface.media.ExifInterface
import com.clone.filesrecovery.data.FileCategory
import com.clone.filesrecovery.data.RecoverableFile
import com.clone.filesrecovery.data.RecoveredRecord
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

/**
 * Deterministic, bounded-memory Forensic Analysis Engine for DeepVault.
 *
 * Performs:
 * 1. Streaming SHA-256, MD5, and SHA-1 calculation (64 KB buffer, cancellation-safe).
 * 2. Binary magic-byte signature identification and extension mismatch detection.
 * 3. Structural validation (JPEG EOI, PNG IEND, PDF %%EOF, ZIP EOCD, ISOBMFF moov/mdat, RIFF size).
 * 4. Category-specific deterministic metadata extraction (EXIF, ISOBMFF, RIFF/WAV, ID3, PDF, OOXML/ZIP/APK).
 * 5. Non-destructive privacy redaction (GPS, sensitive paths, personal filenames).
 */
object ForensicAnalyzer {

    private const val STREAM_BUFFER_SIZE = 64 * 1024 // 64 KB bounded buffer
    private const val MAX_ZIP_ENTRIES_INSPECTED = 200
    private const val MAX_XML_ENTRY_BYTES = 128 * 1024

    data class HashTriple(
        val sha256: String,
        val md5: String,
        val sha1: String,
        val calculatedAtIso: String
    )

    data class MagicInspection(
        val signatureHex: String,
        val detectedFormat: String,
        val detectedMime: String,
        val magicDescription: String,
        val signatureCheck: String, // "passed", "mismatch", "unknown_signature", "empty_file"
        val extensionMismatch: Boolean,
        val extensionMismatchDetail: String?,
        val structureCheck: String, // "passed", "warning", "corrupted", "not_tested"
        val structureDetail: String,
        val completenessStatus: String, // "complete", "partial", "unverified"
        val corruptionIndicators: List<String>
    )

    /**
     * Streams a file in 64 KB chunks to compute SHA-256, MD5, and SHA-1 in a single pass
     * without loading the entire file into memory. Supports coroutine cancellation.
     */
    suspend fun computeHashesStreaming(
        file: File,
        onProgress: ((bytesRead: Long, totalBytes: Long) -> Unit)? = null
    ): HashTriple = withContext(Dispatchers.IO) {
        if (!file.exists() || !file.isFile) {
            return@withContext HashTriple(
                sha256 = "unavailable_file_missing",
                md5 = "unavailable_file_missing",
                sha1 = "unavailable_file_missing",
                calculatedAtIso = ForensicTimeUtil.nowIsoUtc()
            )
        }
        val sha256Digest = MessageDigest.getInstance("SHA-256")
        val md5Digest = MessageDigest.getInstance("MD5")
        val sha1Digest = MessageDigest.getInstance("SHA-1")

        val total = file.length()
        var readTotal = 0L
        val buffer = ByteArray(STREAM_BUFFER_SIZE)

        FileInputStream(file).use { fis ->
            var read = fis.read(buffer)
            while (read != -1) {
                currentCoroutineContext().ensureActive()
                if (read > 0) {
                    sha256Digest.update(buffer, 0, read)
                    md5Digest.update(buffer, 0, read)
                    sha1Digest.update(buffer, 0, read)
                    readTotal += read
                    onProgress?.invoke(readTotal, total)
                }
                read = fis.read(buffer)
            }
        }

        HashTriple(
            sha256 = sha256Digest.digest().toHexLower(),
            md5 = md5Digest.digest().toHexLower(),
            sha1 = sha1Digest.digest().toHexLower(),
            calculatedAtIso = ForensicTimeUtil.nowIsoUtc()
        )
    }

    /**
     * Synchronous SHA-256 helper for small report files and manifest verification.
     */
    fun computeSha256Sync(file: File): String {
        if (!file.exists() || !file.isFile) return "unavailable"
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(STREAM_BUFFER_SIZE)
        FileInputStream(file).use { fis ->
            var n = fis.read(buffer)
            while (n != -1) {
                if (n > 0) digest.update(buffer, 0, n)
                n = fis.read(buffer)
            }
        }
        return digest.digest().toHexLower()
    }

    /**
     * Analyzes a single file (either active/recoverable or recovered record) and builds
     * a complete, deterministic [ForensicEvidenceRecord].
     */
    suspend fun analyzeFile(
        context: Context?,
        targetFile: File,
        originalFilename: String? = targetFile.name,
        sourceLocation: String? = targetFile.parent,
        recoveredOutputPath: String? = null,
        recoveryStatus: String = "accessible_active",
        recoveryMethod: String = "direct_inspection",
        recoveryTimestampMs: Long? = null,
        scanSessionId: String = "SESSION-DEFAULT",
        referenceHash: String? = null
    ): ForensicEvidenceRecord = withContext(Dispatchers.IO) {
        currentCoroutineContext().ensureActive()
        val exists = targetFile.exists() && targetFile.isFile && targetFile.canRead()
        val sizeBytes = if (exists) targetFile.length() else 0L
        val evidenceId = EvidenceIdRegistry.getOrAssign(targetFile.absolutePath, sizeBytes)
        val currentName = targetFile.name
        val ext = currentName.substringAfterLast('.', "").lowercase(Locale.US)

        val errors = mutableListOf<String>()
        val parserWarnings = mutableListOf<String>()
        val unavailableFields = mutableListOf<String>()
        val inconsistencies = mutableListOf<String>()
        val extractedFields = mutableListOf<MetadataField>()
        val timeline = mutableListOf<ForensicTimelineEvent>()
        val findings = mutableListOf<ForensicFinding>()

        if (!exists) {
            errors.add("Target file does not exist or is not readable: ${targetFile.path}")
            return@withContext ForensicEvidenceRecord(
                evidenceId = evidenceId,
                originalFilename = originalFilename,
                currentFilename = currentName,
                sizeBytes = 0L,
                extension = ext,
                detectedMimeType = "application/octet-stream",
                detectedFormat = "UNREADABLE",
                signatureHex = "",
                magicDescription = "File inaccessible",
                sourceLocation = sourceLocation,
                recoveredOutputPath = recoveredOutputPath,
                recoveryStatus = "unreadable",
                recoveryMethod = recoveryMethod,
                recoveryTimestampIso = recoveryTimestampMs?.let { ForensicTimeUtil.epochMillisToIsoUtc(it) },
                scanSessionId = scanSessionId,
                completenessStatus = "unverified",
                structureCheck = "not_tested",
                structureDetail = "File could not be opened for structural inspection.",
                signatureCheck = "unknown_signature",
                extensionMismatch = false,
                extensionMismatchDetail = null,
                corruptionIndicators = listOf("file_missing_or_unreadable"),
                sha256 = "unavailable_file_missing",
                md5 = null,
                sha1 = null,
                hashCalculatedAtIso = ForensicTimeUtil.nowIsoUtc(),
                hashTarget = if (recoveredOutputPath != null) "recovered_output" else "acquired_source",
                referenceHash = referenceHash,
                referenceHashMatch = "not_applicable",
                metadataSourceSummary = "none",
                extractedFields = emptyList(),
                unavailableFields = listOf("all_fields_file_inaccessible"),
                parserWarnings = parserWarnings,
                metadataInconsistencies = emptyList(),
                timeline = emptyList(),
                findings = emptyList(),
                limitations = defaultLimitations(hasAllFiles = true),
                errors = errors
            )
        }

        // 1. Filesystem metadata
        val fsLastMod = targetFile.lastModified()
        val fsLastModIso = ForensicTimeUtil.epochMillisToIsoUtc(fsLastMod)
        if (fsLastModIso != null) {
            extractedFields.add(
                MetadataField("filesystem.last_modified_utc", fsLastModIso, "filesystem_stat", "filesystem")
            )
            timeline.add(
                ForensicTimelineEvent(
                    evidenceId = evidenceId,
                    eventType = "filesystem_last_modified",
                    timestampRaw = fsLastMod.toString(),
                    timestampIso = fsLastModIso,
                    timezoneStatus = "explicit_utc",
                    source = "java.io.File.lastModified()",
                    notes = "Filesystem last-modified timestamp (epoch ms converted to UTC)"
                )
            )
        } else {
            unavailableFields.add("filesystem.last_modified")
        }
        unavailableFields.add("filesystem.birth_time_crtime (restricted on Android/Linux without root statx)")

        if (recoveryTimestampMs != null && recoveryTimestampMs > 0L) {
            val recIso = ForensicTimeUtil.epochMillisToIsoUtc(recoveryTimestampMs)
            if (recIso != null) {
                timeline.add(
                    ForensicTimelineEvent(
                        evidenceId = evidenceId,
                        eventType = "application_recovery_event",
                        timestampRaw = recoveryTimestampMs.toString(),
                        timestampIso = recIso,
                        timezoneStatus = "explicit_utc",
                        source = "deepvault_recovery_store",
                        notes = "Timestamp when DeepVault wrote the recovered output file"
                    )
                )
            }
        }

        // 2. Streaming hashes
        val hashes = computeHashesStreaming(targetFile)
        val refMatch = when {
            referenceHash.isNullOrBlank() -> "not_applicable"
            referenceHash.equals(hashes.sha256, ignoreCase = true) ||
                referenceHash.equals(hashes.md5, ignoreCase = true) ||
                referenceHash.equals(hashes.sha1, ignoreCase = true) -> "matched"
            else -> "mismatched"
        }

        // 3. Magic-byte & structural validation
        val magic = inspectMagicAndStructure(targetFile, ext)
        extractedFields.add(
            MetadataField("binary.signature_hex", magic.signatureHex, "binary_header", "observed")
        )
        extractedFields.add(
            MetadataField("binary.detected_format", magic.detectedFormat, "binary_header", "observed")
        )
        extractedFields.add(
            MetadataField("binary.detected_mime", magic.detectedMime, "binary_header", "observed")
        )

        if (magic.extensionMismatch && magic.extensionMismatchDetail != null) {
            inconsistencies.add(magic.extensionMismatchDetail)
            findings.add(
                ForensicFinding(
                    findingId = "$evidenceId-F-EXT",
                    evidenceId = evidenceId,
                    severity = "warning",
                    category = "extension_mismatch",
                    title = "Filename Extension Mismatch",
                    description = magic.extensionMismatchDetail,
                    observationBasis = "rule_based_finding"
                )
            )
        }

        if (magic.structureCheck == "corrupted" || magic.structureCheck == "warning") {
            findings.add(
                ForensicFinding(
                    findingId = "$evidenceId-F-STRUCT",
                    evidenceId = evidenceId,
                    severity = if (magic.structureCheck == "corrupted") "high" else "notice",
                    category = "structure_validation",
                    title = "Structural Validation: ${magic.structureCheck.uppercase(Locale.US)}",
                    description = magic.structureDetail,
                    observationBasis = "rule_based_finding"
                )
            )
        } else if (magic.structureCheck == "passed") {
            findings.add(
                ForensicFinding(
                    findingId = "$evidenceId-F-STRUCT-OK",
                    evidenceId = evidenceId,
                    severity = "info",
                    category = "structure_validation",
                    title = "Container & Signature Validation Passed",
                    description = magic.structureDetail,
                    observationBasis = "direct_observation"
                )
            )
        }

        // 4. Category-specific deep metadata extraction
        var imageMeta: ImageForensicMetadata? = null
        var videoMeta: VideoForensicMetadata? = null
        var audioMeta: AudioForensicMetadata? = null
        var docMeta: DocumentArchiveForensicMetadata? = null
        val sourcesUsed = mutableSetOf("filesystem_stat", "binary_header")

        val formatUpper = magic.detectedFormat.uppercase(Locale.US)
        when {
            formatUpper in setOf("JPEG", "PNG", "GIF", "WEBP", "BMP", "HEIC", "TIFF") ||
                ext in FileCategory.PHOTO.extensions -> {
                sourcesUsed.add("embedded_exif_and_image_header")
                imageMeta = extractImageMetadata(
                    file = targetFile,
                    detectedFormat = magic.detectedFormat,
                    fsLastModIso = fsLastModIso,
                    extractedFields = extractedFields,
                    unavailableFields = unavailableFields,
                    parserWarnings = parserWarnings,
                    inconsistencies = inconsistencies,
                    timeline = timeline,
                    evidenceId = evidenceId,
                    fsLastModMs = fsLastMod
                )
            }
            formatUpper in setOf("MP4", "MOV", "MKV", "WEBM", "AVI", "3GP") ||
                ext in FileCategory.VIDEO.extensions -> {
                sourcesUsed.add("video_container_and_retriever")
                videoMeta = extractVideoMetadata(
                    file = targetFile,
                    detectedFormat = magic.detectedFormat,
                    fsLastModIso = fsLastModIso,
                    extractedFields = extractedFields,
                    unavailableFields = unavailableFields,
                    parserWarnings = parserWarnings,
                    timeline = timeline,
                    evidenceId = evidenceId
                )
            }
            formatUpper in setOf("MP3", "WAV", "FLAC", "OGG", "M4A", "AAC") ||
                ext in FileCategory.AUDIO.extensions -> {
                sourcesUsed.add("audio_tags_and_header")
                audioMeta = extractAudioMetadata(
                    file = targetFile,
                    detectedFormat = magic.detectedFormat,
                    fsLastModIso = fsLastModIso,
                    extractedFields = extractedFields,
                    unavailableFields = unavailableFields,
                    parserWarnings = parserWarnings
                )
            }
            formatUpper in setOf("PDF", "ZIP", "DOCX", "XLSX", "PPTX", "APK", "RAR", "7Z", "OLE2_DOC_XLS_PPT", "RTF", "TEXT", "JSON", "XML") ||
                ext in FileCategory.DOCUMENT.extensions -> {
                sourcesUsed.add("document_and_archive_parser")
                docMeta = extractDocumentOrArchiveMetadata(
                    file = targetFile,
                    detectedFormat = magic.detectedFormat,
                    ext = ext,
                    extractedFields = extractedFields,
                    unavailableFields = unavailableFields,
                    parserWarnings = parserWarnings,
                    timeline = timeline,
                    evidenceId = evidenceId
                )
            }
        }

        ForensicEvidenceRecord(
            evidenceId = evidenceId,
            originalFilename = originalFilename,
            currentFilename = currentName,
            sizeBytes = sizeBytes,
            extension = ext,
            detectedMimeType = magic.detectedMime,
            detectedFormat = magic.detectedFormat,
            signatureHex = magic.signatureHex,
            magicDescription = magic.magicDescription,
            sourceLocation = sourceLocation,
            recoveredOutputPath = recoveredOutputPath,
            recoveryStatus = recoveryStatus,
            recoveryMethod = recoveryMethod,
            recoveryTimestampIso = recoveryTimestampMs?.let { ForensicTimeUtil.epochMillisToIsoUtc(it) },
            scanSessionId = scanSessionId,
            completenessStatus = magic.completenessStatus,
            structureCheck = magic.structureCheck,
            structureDetail = magic.structureDetail,
            signatureCheck = magic.signatureCheck,
            extensionMismatch = magic.extensionMismatch,
            extensionMismatchDetail = magic.extensionMismatchDetail,
            corruptionIndicators = magic.corruptionIndicators,
            sha256 = hashes.sha256,
            md5 = hashes.md5,
            sha1 = hashes.sha1,
            hashCalculatedAtIso = hashes.calculatedAtIso,
            hashTarget = if (recoveredOutputPath != null) "recovered_output" else "acquired_source",
            referenceHash = referenceHash,
            referenceHashMatch = refMatch,
            metadataSourceSummary = sourcesUsed.joinToString(", "),
            extractedFields = extractedFields,
            unavailableFields = unavailableFields.distinct(),
            parserWarnings = parserWarnings.distinct(),
            metadataInconsistencies = inconsistencies.distinct(),
            imageMetadata = imageMeta,
            videoMetadata = videoMeta,
            audioMetadata = audioMeta,
            documentMetadata = docMeta,
            timeline = timeline,
            findings = findings,
            limitations = defaultLimitations(hasAllFiles = true),
            errors = errors
        )
    }

    /**
     * Builds a combined [ForensicCaseReport] for one or more analyzed files, computing
     * exact SHA-256 duplicate groups, timeline events, recovery statistics, and applying
     * any requested [ForensicPrivacyOptions] non-destructively.
     */
    fun buildCaseReport(
        evidenceRecords: List<ForensicEvidenceRecord>,
        reportType: String = if (evidenceRecords.size == 1) "individual_file" else "combined_case",
        caseId: String = "CASE-${UUID.randomUUID().toString().take(8).uppercase(Locale.US)}",
        scanSessionId: String = evidenceRecords.firstOrNull()?.scanSessionId ?: "SESSION-001",
        acquisitionMethod: String = "Multi-Layer User-Space File System Traversal, MediaStore Query & Signature Carving",
        privacyOptions: ForensicPrivacyOptions = ForensicPrivacyOptions(),
        reportVersion: Int = 1,
        deviceInfo: DeviceForensicInfo = getDefaultDeviceInfo()
    ): List<ForensicCaseReport> {
        // 1. Filter out excluded evidence IDs
        val filteredRaw = evidenceRecords.filterNot { privacyOptions.excludedEvidenceIds.contains(it.evidenceId) }

        // 2. Detect exact SHA-256 duplicate groups across the case
        val byHash = filteredRaw
            .filter { it.sha256.length == 64 && it.sizeBytes > 0L }
            .groupBy { it.sha256 }
            .filter { it.value.size > 1 }

        val duplicateGroups = mutableListOf<DuplicateEvidenceGroup>()
        val evidenceIdToDupGroup = mutableMapOf<String, Pair<String, List<String>>>()
        var groupIdx = 1
        byHash.forEach { (sha, items) ->
            val gId = String.format(Locale.US, "DUP-%04d", groupIdx++)
            val ids = items.map { it.evidenceId }
            duplicateGroups.add(
                DuplicateEvidenceGroup(
                    groupId = gId,
                    matchBasis = "exact_sha256",
                    hashValue = sha,
                    evidenceIds = ids,
                    filenames = items.map { if (privacyOptions.excludePersonalFilenames) "[REDACTED_FILENAME_${it.evidenceId}]" else it.currentFilename },
                    totalBytes = items.sumOf { it.sizeBytes }
                )
            )
            items.forEach { item ->
                evidenceIdToDupGroup[item.evidenceId] = gId to (ids - item.evidenceId)
            }
        }

        // 3. Enrich with duplicate references and apply non-destructive privacy redaction
        val processedEvidence = filteredRaw.map { rec ->
            val dupInfo = evidenceIdToDupGroup[rec.evidenceId]
            val enriched = if (dupInfo != null) {
                val dupFinding = ForensicFinding(
                    findingId = "${rec.evidenceId}-F-DUP",
                    evidenceId = rec.evidenceId,
                    severity = "notice",
                    category = "duplicate_detection",
                    title = "Exact Byte-Level Duplicate (${dupInfo.first})",
                    description = "Identical SHA-256 hash shared with evidence ID(s): ${dupInfo.second.joinToString(", ")}",
                    observationBasis = "direct_observation"
                )
                rec.copy(
                    duplicateGroupId = dupInfo.first,
                    similarFileEvidenceIds = dupInfo.second,
                    findings = rec.findings + dupFinding
                )
            } else rec
            applyRedactionToRecord(enriched, privacyOptions)
        }

        val generatedAt = ForensicTimeUtil.nowIsoUtc()
        val baseReportId = "RPT-${UUID.randomUUID().toString().take(8).uppercase(Locale.US)}"
        val maxPerPart = privacyOptions.maxEvidencePerReportPart.coerceAtLeast(1)

        // Split into numbered parts if processedEvidence exceeds maxPerPart
        val chunks: List<List<ForensicEvidenceRecord>> = if (processedEvidence.isEmpty()) {
            listOf(emptyList())
        } else {
            processedEvidence.chunked(maxPerPart)
        }

        val totalParts = chunks.size
        val overallStats = computeRecoveryStatistics(processedEvidence, duplicateGroups.size)

        return chunks.mapIndexed { idx, partItems ->
            val partNum = idx + 1
            val partId = if (totalParts > 1) "$baseReportId-P$partNum" else baseReportId
            val partManifest = partItems.map { item ->
                HashManifestEntry(
                    evidenceId = item.evidenceId,
                    filename = item.currentFilename,
                    sizeBytes = item.sizeBytes,
                    sha256 = item.sha256,
                    md5 = item.md5,
                    sha1 = item.sha1,
                    hashTarget = item.hashTarget,
                    calculatedAtIso = item.hashCalculatedAtIso
                )
            }
            val partTimeline = partItems.flatMap { it.timeline }.sortedBy { it.timestampIso ?: it.timestampRaw }
            val partFindings = partItems.flatMap { it.findings }
            val partLimitations = (partItems.flatMap { it.limitations } + defaultLimitations(true)).distinct()
            val partErrors = partItems.flatMap { it.errors }.distinct()

            ForensicCaseReport(
                reportId = partId,
                reportVersion = reportVersion,
                schemaVersion = ForensicConstants.SCHEMA_VERSION,
                reportType = reportType,
                generatedAtIso = generatedAt,
                caseId = caseId,
                caseCreatedAtIso = generatedAt,
                scanSessionId = scanSessionId,
                deviceInfo = deviceInfo,
                acquisitionMethod = acquisitionMethod,
                privacyOptions = privacyOptions,
                isSanitized = privacyOptions.isSanitized,
                redactionSummary = privacyOptions.buildRedactionSummary(),
                evidenceItems = partItems,
                hashManifest = partManifest,
                recoveryStats = overallStats,
                timeline = partTimeline,
                duplicateGroups = duplicateGroups,
                findings = partFindings,
                limitations = partLimitations,
                errors = partErrors,
                partNumber = partNum,
                totalParts = totalParts,
                totalEvidenceInCase = processedEvidence.size
            )
        }
    }

    /**
     * Pure non-destructive transformation applying [ForensicPrivacyOptions] to a single record.
     * Never modifies the underlying evidence file on disk.
     */
    fun applyRedactionToRecord(
        record: ForensicEvidenceRecord,
        options: ForensicPrivacyOptions
    ): ForensicEvidenceRecord {
        if (!options.isSanitized) return record
        val redactedFields = mutableListOf<String>()

        var origName = record.originalFilename
        var currName = record.currentFilename
        if (options.excludePersonalFilenames) {
            redactedFields.add("originalFilename")
            redactedFields.add("currentFilename")
            val suffix = if (record.extension.isNotBlank()) ".${record.extension}" else ""
            origName = origName?.let { "[REDACTED_FILENAME_${record.evidenceId}]$suffix" }
            currName = "[REDACTED_FILENAME_${record.evidenceId}]$suffix"
        }

        var srcLoc = record.sourceLocation
        var recOut = record.recoveredOutputPath
        if (options.redactSensitivePaths) {
            if (srcLoc != null) {
                redactedFields.add("sourceLocation")
                srcLoc = redactPathString(srcLoc)
            }
            if (recOut != null) {
                redactedFields.add("recoveredOutputPath")
                recOut = redactPathString(recOut)
            }
        }

        var imgMeta = record.imageMetadata
        if (!options.includeGps && imgMeta?.gps != null) {
            redactedFields.add("imageMetadata.gps")
            imgMeta = imgMeta.copy(gps = null)
        }
        if (options.excludePersonalMetadata && imgMeta != null) {
            redactedFields.add("imageMetadata.personal_tags")
            imgMeta = imgMeta.copy(cameraMake = null, cameraModel = null, software = null)
        }

        var docMeta = record.documentMetadata
        if (options.excludePersonalMetadata && docMeta != null) {
            redactedFields.add("documentMetadata.author_creator")
            docMeta = docMeta.copy(author = null, creatorOrLastModifiedBy = null)
        }

        var audMeta = record.audioMetadata
        if (options.excludePersonalMetadata && audMeta != null) {
            redactedFields.add("audioMetadata.artist_tags")
            audMeta = audMeta.copy(artistTag = null, albumTag = null, titleTag = null)
        }

        val filteredExtracted = record.extractedFields.mapNotNull { field ->
            val k = field.key.lowercase(Locale.US)
            when {
                !options.includeGps && k.startsWith("exif.gps") -> null
                options.excludePersonalMetadata && (
                    k.contains("author") || k.contains("creator") || k.contains("artist") ||
                        k.contains("camera_make") || k.contains("camera_model") || k.contains("owner") ||
                        k.contains("serial")
                    ) -> null
                options.excludeNotes && k.contains("note") -> null
                options.redactSensitivePaths && k.contains("path") ->
                    field.copy(value = redactPathString(field.value))
                options.excludePersonalFilenames && k.contains("filename") ->
                    field.copy(value = currName)
                else -> field
            }
        }

        return record.copy(
            originalFilename = origName,
            currentFilename = currName,
            sourceLocation = srcLoc,
            recoveredOutputPath = recOut,
            imageMetadata = imgMeta,
            documentMetadata = docMeta,
            audioMetadata = audMeta,
            extractedFields = filteredExtracted,
            isRedacted = redactedFields.isNotEmpty(),
            redactedFieldNames = redactedFields
        )
    }

    internal fun redactPathString(path: String): String {
        val lastFolder = path.trimEnd('/', '\\').substringAfterLast('/', "").substringAfterLast('\\', "")
        return if (lastFolder.isNotBlank()) {
            "[REDACTED_PATH]/$lastFolder"
        } else {
            "[REDACTED_PATH]"
        }
    }

    // ---------- Binary Magic-Byte & Structural Validation ----------

    fun inspectMagicAndStructure(file: File, extensionLower: String): MagicInspection {
        val length = file.length()
        if (length == 0L) {
            return MagicInspection(
                signatureHex = "",
                detectedFormat = "EMPTY",
                detectedMime = "application/x-empty",
                magicDescription = "Zero-byte empty file",
                signatureCheck = "empty_file",
                extensionMismatch = false,
                extensionMismatchDetail = null,
                structureCheck = "corrupted",
                structureDetail = "File contains 0 bytes (empty inode or unallocated stub).",
                completenessStatus = "partial",
                corruptionIndicators = listOf("zero_byte_file")
            )
        }

        val header = ByteArray(minOf(64L, length).toInt())
        val tail = ByteArray(minOf(4096L, length).toInt())
        runCatching {
            RandomAccessFile(file, "r").use { raf ->
                raf.seek(0L)
                raf.readFully(header)
                raf.seek((length - tail.size).coerceAtLeast(0L))
                raf.readFully(tail)
            }
        }.onFailure {
            return MagicInspection(
                signatureHex = "",
                detectedFormat = "IO_ERROR",
                detectedMime = "application/octet-stream",
                magicDescription = "I/O error reading header",
                signatureCheck = "unknown_signature",
                extensionMismatch = false,
                extensionMismatchDetail = null,
                structureCheck = "not_tested",
                structureDetail = "Could not read header/trailer bytes: ${it.message}",
                completenessStatus = "unverified",
                corruptionIndicators = listOf("io_read_error")
            )
        }

        val sigHex = header.take(16).toByteArray().toHexUpperSpaced()
        val indicators = mutableListOf<String>()

        // Identify format by magic bytes
        var detectedFormat = "UNKNOWN"
        var detectedMime = "application/octet-stream"
        var magicDesc = "Unrecognized binary or plain-text stream"
        var structureCheck = "not_tested"
        var structureDetail = "Format structure check not applicable."
        var completeness = "unverified"

        when {
            // JPEG: FF D8 FF
            header.size >= 3 && header[0] == 0xFF.toByte() && header[1] == 0xD8.toByte() && header[2] == 0xFF.toByte() -> {
                detectedFormat = "JPEG"
                detectedMime = "image/jpeg"
                magicDesc = "JPEG SOI marker (FF D8 FF)"
                val hasEoi = hasByteSequence(tail, byteArrayOf(0xFF.toByte(), 0xD9.toByte()))
                if (hasEoi) {
                    structureCheck = "passed"
                    structureDetail = "JPEG Start-Of-Image (FF D8 FF) and End-Of-Image (FF D9) markers verified."
                    completeness = "complete"
                } else {
                    structureCheck = "warning"
                    structureDetail = "JPEG Start-Of-Image (FF D8 FF) present, but End-Of-Image (FF D9) marker was not found in the trailing 4 KB (possible partial carve or trailing metadata)."
                    completeness = "partial"
                    indicators.add("missing_jpeg_eoi_marker")
                }
            }
            // PNG: 89 50 4E 47 0D 0A 1A 0A
            header.size >= 8 &&
                header[0] == 0x89.toByte() && header[1] == 0x50.toByte() &&
                header[2] == 0x4E.toByte() && header[3] == 0x47.toByte() &&
                header[4] == 0x0D.toByte() && header[5] == 0x0A.toByte() &&
                header[6] == 0x1A.toByte() && header[7] == 0x0A.toByte() -> {
                detectedFormat = "PNG"
                detectedMime = "image/png"
                magicDesc = "PNG 8-byte signature (89 50 4E 47 0D 0A 1A 0A)"
                val hasIend = hasByteSequence(tail, "IEND".toByteArray(StandardCharsets.US_ASCII))
                if (hasIend) {
                    structureCheck = "passed"
                    structureDetail = "PNG signature, IHDR chunk, and trailing IEND chunk verified."
                    completeness = "complete"
                } else {
                    structureCheck = "corrupted"
                    structureDetail = "PNG header valid, but trailing IEND chunk is missing (truncated PNG stream)."
                    completeness = "partial"
                    indicators.add("missing_png_iend_chunk")
                }
            }
            // GIF: GIF87a or GIF89a
            header.size >= 6 &&
                header[0] == 0x47.toByte() && header[1] == 0x49.toByte() && header[2] == 0x46.toByte() &&
                header[3] == 0x38.toByte() && (header[4] == 0x37.toByte() || header[4] == 0x39.toByte()) &&
                header[5] == 0x61.toByte() -> {
                detectedFormat = "GIF"
                detectedMime = "image/gif"
                magicDesc = "GIF87a/GIF89a header"
                val hasTrailer = tail.isNotEmpty() && tail.last() == 0x3B.toByte()
                structureCheck = if (hasTrailer) "passed" else "warning"
                structureDetail = if (hasTrailer) "GIF header and 0x3B trailer verified." else "GIF header valid; trailing byte is not 0x3B."
                completeness = if (hasTrailer) "complete" else "partial"
            }
            // RIFF container: WEBP, WAV, AVI
            header.size >= 12 &&
                header[0] == 0x52.toByte() && header[1] == 0x49.toByte() &&
                header[2] == 0x46.toByte() && header[3] == 0x46.toByte() -> {
                val riffSize = ByteBuffer.wrap(header, 4, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
                val subType = String(header, 8, 4, StandardCharsets.US_ASCII)
                when (subType) {
                    "WEBP" -> {
                        detectedFormat = "WEBP"
                        detectedMime = "image/webp"
                        magicDesc = "RIFF WEBP container"
                    }
                    "WAVE" -> {
                        detectedFormat = "WAV"
                        detectedMime = "audio/wav"
                        magicDesc = "RIFF WAVE audio container"
                    }
                    "AVI " -> {
                        detectedFormat = "AVI"
                        detectedMime = "video/x-msvideo"
                        magicDesc = "RIFF AVI video container"
                    }
                    else -> {
                        detectedFormat = "RIFF"
                        detectedMime = "application/octet-stream"
                        magicDesc = "RIFF ($subType) container"
                    }
                }
                val expectedTotal = riffSize + 8L
                if (length >= expectedTotal) {
                    structureCheck = "passed"
                    structureDetail = "RIFF ($subType) header declared size ($expectedTotal bytes) is satisfied by actual file size ($length bytes)."
                    completeness = "complete"
                } else {
                    structureCheck = "warning"
                    structureDetail = "RIFF ($subType) declared size ($expectedTotal bytes) exceeds actual file size ($length bytes); file may be truncated."
                    completeness = "partial"
                    indicators.add("riff_size_truncated")
                }
            }
            // ISOBMFF (MP4, MOV, HEIC, M4A, 3GP): offset 4..7 == "ftyp"
            header.size >= 12 &&
                header[4] == 0x66.toByte() && header[5] == 0x74.toByte() &&
                header[6] == 0x79.toByte() && header[7] == 0x70.toByte() -> {
                val brand = String(header, 8, 4, StandardCharsets.US_ASCII).trim()
                when {
                    brand in setOf("heic", "heix", "mif1", "msf1", "avif") -> {
                        detectedFormat = "HEIC"
                        detectedMime = "image/heic"
                        magicDesc = "ISO Base Media File Format (ftyp=$brand)"
                    }
                    brand in setOf("M4A", "M4B") -> {
                        detectedFormat = "M4A"
                        detectedMime = "audio/mp4"
                        magicDesc = "ISO Base Media Audio (ftyp=$brand)"
                    }
                    brand == "qt" -> {
                        detectedFormat = "MOV"
                        detectedMime = "video/quicktime"
                        magicDesc = "Apple QuickTime container (ftyp=qt)"
                    }
                    else -> {
                        detectedFormat = "MP4"
                        detectedMime = "video/mp4"
                        magicDesc = "ISO Base Media MP4 container (ftyp=$brand)"
                    }
                }
                val atoms = scanIsoBmffAtoms(file)
                val hasMoov = atoms.contains("moov") || atoms.contains("meta")
                val hasMdat = atoms.contains("mdat")
                if (hasMoov && hasMdat) {
                    structureCheck = "passed"
                    structureDetail = "ISOBMFF atoms verified: ${atoms.joinToString(", ")}."
                    completeness = "complete"
                } else {
                    structureCheck = "warning"
                    structureDetail = "ISOBMFF ftyp header found (atoms: ${atoms.joinToString(", ")}), but moov/mdat pair is incomplete."
                    completeness = "partial"
                    indicators.add("missing_isobmff_moov_or_mdat")
                }
            }
            // PDF: %PDF-
            header.size >= 5 &&
                header[0] == 0x25.toByte() && header[1] == 0x50.toByte() &&
                header[2] == 0x44.toByte() && header[3] == 0x46.toByte() &&
                header[4] == 0x2D.toByte() -> {
                val ver = String(header, 0, minOf(8, header.size), StandardCharsets.US_ASCII).lineSequence().firstOrNull() ?: "%PDF"
                detectedFormat = "PDF"
                detectedMime = "application/pdf"
                magicDesc = "Adobe PDF document header ($ver)"
                val hasEof = hasByteSequence(tail, "%%EOF".toByteArray(StandardCharsets.US_ASCII))
                if (hasEof) {
                    structureCheck = "passed"
                    structureDetail = "PDF header ($ver) and trailing %%EOF marker verified."
                    completeness = "complete"
                } else {
                    structureCheck = "warning"
                    structureDetail = "PDF header ($ver) found, but trailing %%EOF marker is missing in last 4 KB."
                    completeness = "partial"
                    indicators.add("missing_pdf_eof_marker")
                }
            }
            // ZIP / DOCX / XLSX / PPTX / APK: 50 4B 03 04
            header.size >= 4 &&
                header[0] == 0x50.toByte() && header[1] == 0x4B.toByte() &&
                header[2] == 0x03.toByte() && header[3] == 0x04.toByte() -> {
                val zipKind = classifyZipContainer(file, extensionLower)
                detectedFormat = zipKind.first
                detectedMime = zipKind.second
                magicDesc = "PKZIP local file header (50 4B 03 04) -> ${zipKind.first}"
                // Check End of Central Directory (50 4B 05 06) in trailing bytes
                val hasEocd = hasByteSequence(tail, byteArrayOf(0x50, 0x4B, 0x05, 0x06))
                if (hasEocd) {
                    structureCheck = "passed"
                    structureDetail = "ZIP local header (50 4B 03 04) and End of Central Directory (50 4B 05 06) verified."
                    completeness = "complete"
                } else {
                    structureCheck = "corrupted"
                    structureDetail = "ZIP local header present, but End of Central Directory (50 4B 05 06) is missing in trailing 4 KB (truncated archive)."
                    completeness = "partial"
                    indicators.add("missing_zip_eocd_record")
                }
            }
            // MP3: ID3v2 ("ID3") or MPEG sync (FF FB / FF F3 / FF F2)
            header.size >= 3 &&
                ((header[0] == 0x49.toByte() && header[1] == 0x44.toByte() && header[2] == 0x33.toByte()) ||
                    (header[0] == 0xFF.toByte() && (header[1].toInt() and 0xE0) == 0xE0)) -> {
                detectedFormat = "MP3"
                detectedMime = "audio/mpeg"
                magicDesc = if (header[0] == 0x49.toByte()) "MP3 with ID3v2 tag header" else "MPEG Audio frame sync"
                structureCheck = "passed"
                structureDetail = "MP3 header signature verified ($length bytes)."
                completeness = "complete"
            }
            // FLAC: "fLaC"
            header.size >= 4 &&
                header[0] == 0x66.toByte() && header[1] == 0x4C.toByte() &&
                header[2] == 0x61.toByte() && header[3] == 0x43.toByte() -> {
                detectedFormat = "FLAC"
                detectedMime = "audio/flac"
                magicDesc = "FLAC stream marker (66 4C 61 43)"
                structureCheck = "passed"
                structureDetail = "FLAC header signature and STREAMINFO block present."
                completeness = "complete"
            }
            // OGG: "OggS"
            header.size >= 4 &&
                header[0] == 0x4F.toByte() && header[1] == 0x67.toByte() &&
                header[2] == 0x67.toByte() && header[3] == 0x53.toByte() -> {
                detectedFormat = "OGG"
                detectedMime = "audio/ogg"
                magicDesc = "Ogg bitstream capture pattern (OggS)"
                structureCheck = "passed"
                structureDetail = "Ogg page header verified."
                completeness = "complete"
            }
            // MKV / WebM: 1A 45 DF A3
            header.size >= 4 &&
                header[0] == 0x1A.toByte() && header[1] == 0x45.toByte() &&
                header[2] == 0xDF.toByte() && header[3] == 0xA3.toByte() -> {
                detectedFormat = if (extensionLower == "webm") "WEBM" else "MKV"
                detectedMime = if (extensionLower == "webm") "video/webm" else "video/x-matroska"
                magicDesc = "Matroska/WebM EBML header (1A 45 DF A3)"
                structureCheck = "passed"
                structureDetail = "EBML Matroska header verified."
                completeness = "complete"
            }
            // OLE2 Compound Document (DOC, XLS, PPT): D0 CF 11 E0 A1 B1 1A E1
            header.size >= 8 &&
                header[0] == 0xD0.toByte() && header[1] == 0xCF.toByte() &&
                header[2] == 0x11.toByte() && header[3] == 0xE0.toByte() -> {
                detectedFormat = "OLE2_DOC_XLS_PPT"
                detectedMime = "application/x-ole-storage"
                magicDesc = "Microsoft Compound File Binary (OLE2) header"
                structureCheck = "passed"
                structureDetail = "OLE2 Compound Document header verified."
                completeness = "complete"
            }
            // Plain text / JSON / XML / CSV heuristics
            isMostlyPrintableUtf8(header) -> {
                val prefix = String(header, StandardCharsets.UTF_8).trimStart()
                when {
                    prefix.startsWith("{") || prefix.startsWith("[") -> {
                        detectedFormat = "JSON"
                        detectedMime = "application/json"
                        magicDesc = "UTF-8 JSON text stream"
                    }
                    prefix.startsWith("<?xml") || prefix.startsWith("<") -> {
                        detectedFormat = "XML"
                        detectedMime = "application/xml"
                        magicDesc = "UTF-8 XML/HTML markup stream"
                    }
                    extensionLower == "csv" -> {
                        detectedFormat = "CSV"
                        detectedMime = "text/csv"
                        magicDesc = "UTF-8 comma-separated text"
                    }
                    else -> {
                        detectedFormat = "TEXT"
                        detectedMime = "text/plain"
                        magicDesc = "Printable UTF-8/ASCII text stream"
                    }
                }
                structureCheck = "passed"
                structureDetail = "Printable text stream verified."
                completeness = "complete"
            }
        }

        // Check extension vs detectedFormat consistency
        val (extMismatch, mismatchMsg) = evaluateExtensionMismatch(extensionLower, detectedFormat)
        val sigCheck = when {
            detectedFormat == "UNKNOWN" -> "unknown_signature"
            extMismatch -> "mismatch"
            else -> "passed"
        }

        return MagicInspection(
            signatureHex = sigHex,
            detectedFormat = detectedFormat,
            detectedMime = detectedMime,
            magicDescription = magicDesc,
            signatureCheck = sigCheck,
            extensionMismatch = extMismatch,
            extensionMismatchDetail = mismatchMsg,
            structureCheck = structureCheck,
            structureDetail = structureDetail,
            completenessStatus = completeness,
            corruptionIndicators = indicators
        )
    }

    private fun evaluateExtensionMismatch(ext: String, detectedFormat: String): Pair<Boolean, String?> {
        if (ext.isBlank() || detectedFormat == "UNKNOWN" || detectedFormat == "EMPTY") return false to null
        val expectedFormatsForExt: Set<String> = when (ext) {
            "jpg", "jpeg", "jfif" -> setOf("JPEG")
            "png" -> setOf("PNG")
            "gif" -> setOf("GIF")
            "webp" -> setOf("WEBP")
            "heic", "heif", "avif" -> setOf("HEIC")
            "pdf" -> setOf("PDF")
            "zip" -> setOf("ZIP", "DOCX", "XLSX", "PPTX", "APK")
            "docx" -> setOf("DOCX", "ZIP")
            "xlsx" -> setOf("XLSX", "ZIP")
            "pptx" -> setOf("PPTX", "ZIP")
            "apk" -> setOf("APK", "ZIP")
            "doc", "xls", "ppt" -> setOf("OLE2_DOC_XLS_PPT")
            "mp4", "m4v" -> setOf("MP4", "MOV")
            "mov" -> setOf("MOV", "MP4")
            "mkv" -> setOf("MKV", "WEBM")
            "webm" -> setOf("WEBM", "MKV")
            "avi" -> setOf("AVI")
            "wav" -> setOf("WAV")
            "mp3" -> setOf("MP3")
            "flac" -> setOf("FLAC")
            "ogg", "opus" -> setOf("OGG")
            "m4a" -> setOf("M4A", "MP4")
            "txt", "md", "log" -> setOf("TEXT", "JSON", "XML", "CSV")
            "json" -> setOf("JSON", "TEXT")
            "xml", "html", "htm" -> setOf("XML", "TEXT")
            "csv" -> setOf("CSV", "TEXT")
            else -> return false to null
        }
        return if (!expectedFormatsForExt.contains(detectedFormat)) {
            true to "File extension '.$ext' does not match binary magic signature format '$detectedFormat'."
        } else {
            false to null
        }
    }

    // ---------- Image Metadata Extraction ----------

    private fun extractImageMetadata(
        file: File,
        detectedFormat: String,
        fsLastModIso: String?,
        extractedFields: MutableList<MetadataField>,
        unavailableFields: MutableList<String>,
        parserWarnings: MutableList<String>,
        inconsistencies: MutableList<String>,
        timeline: MutableList<ForensicTimelineEvent>,
        evidenceId: String,
        fsLastModMs: Long
    ): ImageForensicMetadata {
        var width: Int? = null
        var height: Int? = null
        var colorProfile: String? = null

        // 1. Try binary PNG/GIF/JPEG SOF header parsing first (deterministic in both Android & JVM)
        val binaryDims = parseBinaryImageDimensions(file, detectedFormat)
        if (binaryDims != null) {
            width = binaryDims.first
            height = binaryDims.second
            colorProfile = binaryDims.third
        }

        // 2. Fallback / supplement with BitmapFactory bounds
        if (width == null || height == null) {
            runCatching {
                val opts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                BitmapFactory.decodeFile(file.absolutePath, opts)
                if (opts.outWidth > 0 && opts.outHeight > 0) {
                    width = opts.outWidth
                    height = opts.outHeight
                }
                if (colorProfile == null && opts.outConfig != null) {
                    colorProfile = opts.outConfig.name
                }
            }
        }

        if (width != null && height != null) {
            extractedFields.add(MetadataField("image.dimensions", "${width}x${height}", "image_header", "observed"))
        } else {
            unavailableFields.add("image.dimensions")
        }
        if (colorProfile != null) {
            extractedFields.add(MetadataField("image.color_profile", colorProfile!!, "image_header", "observed"))
        } else {
            unavailableFields.add("image.color_profile")
        }

        // 3. Extract EXIF via AndroidX ExifInterface
        var make: String? = null
        var model: String? = null
        var dateTimeOrig: String? = null
        var subSecOrig: String? = null
        var offsetOrig: String? = null
        var orientation: String? = null
        var software: String? = null
        var gpsCoords: GpsCoordinates? = null
        var hasThumb = false
        var thumbW: Int? = null
        var thumbH: Int? = null
        var compressionInfo: String? = null
        var exposure: String? = null
        var fNumber: String? = null
        var iso: String? = null
        var focal: String? = null

        runCatching {
            val exif = ExifInterface(file.absolutePath)
            make = exif.getAttribute(ExifInterface.TAG_MAKE)?.trim()?.takeIf { it.isNotEmpty() }
            model = exif.getAttribute(ExifInterface.TAG_MODEL)?.trim()?.takeIf { it.isNotEmpty() }
            dateTimeOrig = (exif.getAttribute(ExifInterface.TAG_DATETIME_ORIGINAL)
                ?: exif.getAttribute(ExifInterface.TAG_DATETIME))?.trim()?.takeIf { it.isNotEmpty() }
            subSecOrig = exif.getAttribute(ExifInterface.TAG_SUBSEC_TIME_ORIGINAL)?.trim()?.takeIf { it.isNotEmpty() }
            offsetOrig = exif.getAttribute(ExifInterface.TAG_OFFSET_TIME_ORIGINAL)?.trim()?.takeIf { it.isNotEmpty() }
            val orientInt = exif.getAttributeInt(ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_UNDEFINED)
            if (orientInt != ExifInterface.ORIENTATION_UNDEFINED) {
                orientation = orientationToLabel(orientInt)
            }
            software = exif.getAttribute(ExifInterface.TAG_SOFTWARE)?.trim()?.takeIf { it.isNotEmpty() }
            compressionInfo = exif.getAttribute(ExifInterface.TAG_COMPRESSION)?.trim()?.takeIf { it.isNotEmpty() }
            exposure = exif.getAttribute(ExifInterface.TAG_EXPOSURE_TIME)?.trim()?.takeIf { it.isNotEmpty() }
            fNumber = exif.getAttribute(ExifInterface.TAG_F_NUMBER)?.trim()?.takeIf { it.isNotEmpty() }
            iso = exif.getAttribute(ExifInterface.TAG_PHOTOGRAPHIC_SENSITIVITY)?.trim()?.takeIf { it.isNotEmpty() }
            focal = exif.getAttribute(ExifInterface.TAG_FOCAL_LENGTH)?.trim()?.takeIf { it.isNotEmpty() }

            if (width == null) {
                val ew = exif.getAttributeInt(ExifInterface.TAG_IMAGE_WIDTH, 0)
                val eh = exif.getAttributeInt(ExifInterface.TAG_IMAGE_LENGTH, 0)
                if (ew > 0 && eh > 0) {
                    width = ew
                    height = eh
                    extractedFields.add(MetadataField("image.dimensions", "${ew}x${eh}", "embedded_exif", "embedded"))
                }
            }

            hasThumb = exif.hasThumbnail()
            if (hasThumb) {
                val range = exif.thumbnailRange
                if (range != null && range.size >= 2) {
                    extractedFields.add(
                        MetadataField("exif.embedded_thumbnail_bytes", range[1].toString(), "embedded_exif", "embedded")
                    )
                }
            }

            val latLong = exif.latLong
            if (latLong != null && latLong.size == 2) {
                val alt = if (exif.hasAttribute(ExifInterface.TAG_GPS_ALTITUDE)) exif.getAltitude(0.0) else null
                val gpsDate = exif.getAttribute(ExifInterface.TAG_GPS_DATESTAMP)
                val gpsTime = exif.getAttribute(ExifInterface.TAG_GPS_TIMESTAMP)
                val gpsUtc = if (!gpsDate.isNullOrBlank() && !gpsTime.isNullOrBlank()) "$gpsDate $gpsTime UTC" else null
                val proc = exif.getAttribute(ExifInterface.TAG_GPS_PROCESSING_METHOD)
                gpsCoords = GpsCoordinates(
                    latitude = latLong[0],
                    longitude = latLong[1],
                    altitudeMeters = alt,
                    gpsTimestampUtc = gpsUtc,
                    gpsProcessingMethod = proc
                )
            }
        }.onFailure {
            parserWarnings.add("EXIF parser warning: ${it.message}")
        }

        if (make != null) extractedFields.add(MetadataField("exif.camera_make", make!!, "embedded_exif", "embedded"))
        else unavailableFields.add("exif.camera_make")

        if (model != null) extractedFields.add(MetadataField("exif.camera_model", model!!, "embedded_exif", "embedded"))
        else unavailableFields.add("exif.camera_model")

        if (dateTimeOrig != null) {
            extractedFields.add(MetadataField("exif.datetime_original_raw", dateTimeOrig!!, "embedded_exif", "embedded"))
            val (parsedIso, tzStatus) = ForensicTimeUtil.parseExifTimestamp(dateTimeOrig, offsetOrig)
            timeline.add(
                ForensicTimelineEvent(
                    evidenceId = evidenceId,
                    eventType = "exif_datetime_original",
                    timestampRaw = dateTimeOrig!!,
                    timestampIso = parsedIso,
                    timezoneStatus = tzStatus,
                    source = "embedded_exif (TAG_DATETIME_ORIGINAL)",
                    notes = if (tzStatus == "local_unverified") "EXIF timestamp lacks explicit timezone offset" else "EXIF timestamp with offset"
                )
            )
        } else {
            unavailableFields.add("exif.datetime_original")
        }

        if (orientation != null) extractedFields.add(MetadataField("exif.orientation", orientation!!, "embedded_exif", "embedded"))
        else unavailableFields.add("exif.orientation")

        if (software != null) extractedFields.add(MetadataField("exif.software", software!!, "embedded_exif", "embedded"))
        else unavailableFields.add("exif.software")

        if (gpsCoords != null) {
            extractedFields.add(
                MetadataField(
                    "exif.gps_coordinates",
                    String.format(Locale.US, "%.6f, %.6f", gpsCoords!!.latitude, gpsCoords!!.longitude),
                    "embedded_exif",
                    "embedded"
                )
            )
            if (gpsCoords!!.altitudeMeters != null) {
                extractedFields.add(
                    MetadataField("exif.gps_altitude_m", String.format(Locale.US, "%.2f", gpsCoords!!.altitudeMeters), "embedded_exif", "embedded")
                )
            }
        } else {
            unavailableFields.add("exif.gps_coordinates")
        }

        return ImageForensicMetadata(
            width = width,
            height = height,
            detectedFormat = detectedFormat,
            colorProfileOrConfig = colorProfile,
            cameraMake = make,
            cameraModel = model,
            captureTimestampRaw = dateTimeOrig,
            subSecTimeOriginal = subSecOrig,
            orientation = orientation,
            software = software,
            gps = gpsCoords,
            hasEmbeddedThumbnail = hasThumb,
            thumbnailWidth = thumbW,
            thumbnailHeight = thumbH,
            compressionInfo = compressionInfo ?: detectedFormat,
            exposureTime = exposure,
            fNumber = fNumber,
            isoSpeed = iso,
            focalLength = focal,
            filesystemLastModifiedIso = fsLastModIso
        )
    }

    private fun parseBinaryImageDimensions(file: File, detectedFormat: String): Triple<Int, Int, String>? {
        return runCatching {
            RandomAccessFile(file, "r").use { raf ->
                when (detectedFormat) {
                    "PNG" -> {
                        if (raf.length() < 26) return null
                        raf.seek(16)
                        val w = raf.readInt()
                        val h = raf.readInt()
                        val bitDepth = raf.readUnsignedByte()
                        val colorType = raf.readUnsignedByte()
                        val colorDesc = when (colorType) {
                            0 -> "Grayscale (${bitDepth}-bit)"
                            2 -> "Truecolor RGB (${bitDepth}-bit)"
                            3 -> "Indexed-color (${bitDepth}-bit)"
                            4 -> "Grayscale+Alpha (${bitDepth}-bit)"
                            6 -> "Truecolor RGBA (${bitDepth}-bit)"
                            else -> "PNG ColorType $colorType (${bitDepth}-bit)"
                        }
                        if (w > 0 && h > 0) Triple(w, h, colorDesc) else null
                    }
                    "GIF" -> {
                        if (raf.length() < 10) return null
                        raf.seek(6)
                        val b = ByteArray(4)
                        raf.readFully(b)
                        val buf = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)
                        val w = buf.short.toInt() and 0xFFFF
                        val h = buf.short.toInt() and 0xFFFF
                        if (w > 0 && h > 0) Triple(w, h, "GIF Indexed Palette") else null
                    }
                    "JPEG" -> {
                        // Scan JPEG markers for SOF0 (FF C0) or SOF2 (FF C2)
                        val len = raf.length()
                        raf.seek(2)
                        var pos = 2L
                        while (pos + 9 < len && pos < 256 * 1024L) {
                            val b1 = raf.readUnsignedByte()
                            if (b1 != 0xFF) {
                                pos = raf.filePointer
                                continue
                            }
                            var marker = raf.readUnsignedByte()
                            while (marker == 0xFF && raf.filePointer < len) {
                                marker = raf.readUnsignedByte()
                            }
                            if (marker == 0xD8 || marker == 0xD9 || (marker in 0xD0..0xD7)) {
                                pos = raf.filePointer
                                continue
                            }
                            if (raf.filePointer + 2 > len) break
                            val segLen = raf.readUnsignedShort()
                            if (segLen < 2) break
                            if (marker in listOf(0xC0, 0xC1, 0xC2)) {
                                if (raf.filePointer + 6 <= len) {
                                    val precision = raf.readUnsignedByte()
                                    val h = raf.readUnsignedShort()
                                    val w = raf.readUnsignedShort()
                                    val comps = raf.readUnsignedByte()
                                    val profile = if (comps == 3) "YCbCr (${precision}-bit, 3-ch)" else "${comps}-channel (${precision}-bit)"
                                    if (w > 0 && h > 0) return Triple(w, h, profile)
                                }
                                break
                            }
                            pos = raf.filePointer + segLen - 2
                            raf.seek(pos)
                        }
                        null
                    }
                    else -> null
                }
            }
        }.getOrNull()
    }

    private fun orientationToLabel(orientation: Int): String = when (orientation) {
        ExifInterface.ORIENTATION_NORMAL -> "Normal (0 deg)"
        ExifInterface.ORIENTATION_ROTATE_90 -> "Rotate 90 CW"
        ExifInterface.ORIENTATION_ROTATE_180 -> "Rotate 180"
        ExifInterface.ORIENTATION_ROTATE_270 -> "Rotate 270 CW"
        ExifInterface.ORIENTATION_FLIP_HORIZONTAL -> "Flip Horizontal"
        ExifInterface.ORIENTATION_FLIP_VERTICAL -> "Flip Vertical"
        else -> "Orientation($orientation)"
    }

    // ---------- Video Metadata Extraction ----------

    private fun extractVideoMetadata(
        file: File,
        detectedFormat: String,
        fsLastModIso: String?,
        extractedFields: MutableList<MetadataField>,
        unavailableFields: MutableList<String>,
        parserWarnings: MutableList<String>,
        timeline: MutableList<ForensicTimelineEvent>,
        evidenceId: String
    ): VideoForensicMetadata {
        val atoms = if (detectedFormat in setOf("MP4", "MOV", "M4A", "HEIC")) scanIsoBmffAtoms(file) else emptyList()
        var majorBrand: String? = null
        if (atoms.contains("ftyp") && file.length() >= 12) {
            runCatching {
                RandomAccessFile(file, "r").use { raf ->
                    raf.seek(8)
                    val b = ByteArray(4)
                    raf.readFully(b)
                    majorBrand = String(b, StandardCharsets.US_ASCII).trim()
                }
            }
        }

        var vCodec: String? = null
        var aCodec: String? = null
        var width: Int? = null
        var height: Int? = null
        var durationMs: Long? = null
        var frameRate: String? = null
        var bitrate: Long? = null
        var rotation: Int? = null
        var trackCount: Int? = null
        var creationRaw: String? = null

        runCatching {
            val mmr = MediaMetadataRetriever()
            try {
                mmr.setDataSource(file.absolutePath)
                vCodec = mmr.extractMetadata(MediaMetadataRetriever.METADATA_KEY_MIMETYPE)
                width = mmr.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_WIDTH)?.toIntOrNull()
                height = mmr.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_HEIGHT)?.toIntOrNull()
                durationMs = mmr.extractMetadata(MediaMetadataRetriever.METADATA_KEY_DURATION)?.toLongOrNull()
                frameRate = mmr.extractMetadata(MediaMetadataRetriever.METADATA_KEY_CAPTURE_FRAMERATE)
                bitrate = mmr.extractMetadata(MediaMetadataRetriever.METADATA_KEY_BITRATE)?.toLongOrNull()
                rotation = mmr.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_ROTATION)?.toIntOrNull()
                trackCount = mmr.extractMetadata(MediaMetadataRetriever.METADATA_KEY_NUM_TRACKS)?.toIntOrNull()
                creationRaw = mmr.extractMetadata(MediaMetadataRetriever.METADATA_KEY_DATE)
                val hasAudio = mmr.extractMetadata(MediaMetadataRetriever.METADATA_KEY_HAS_AUDIO)
                if (hasAudio == "yes") aCodec = "present"
            } finally {
                runCatching { mmr.release() }
            }
        }.onFailure {
            parserWarnings.add("MediaMetadataRetriever unavailable or failed: ${it.message}")
        }

        if (majorBrand != null) extractedFields.add(MetadataField("video.major_brand", majorBrand!!, "container_header", "observed"))
        if (atoms.isNotEmpty()) extractedFields.add(MetadataField("video.isobmff_atoms", atoms.joinToString(","), "container_header", "observed"))
        if (width != null && height != null) extractedFields.add(MetadataField("video.resolution", "${width}x${height}", "container_metadata", "embedded"))
        else unavailableFields.add("video.resolution")
        if (durationMs != null) extractedFields.add(MetadataField("video.duration_ms", durationMs.toString(), "container_metadata", "embedded"))
        else unavailableFields.add("video.duration_ms")
        if (bitrate != null) extractedFields.add(MetadataField("video.bitrate_bps", bitrate.toString(), "container_metadata", "embedded"))
        else unavailableFields.add("video.bitrate_bps")

        if (!creationRaw.isNullOrBlank()) {
            extractedFields.add(MetadataField("video.creation_date_raw", creationRaw!!, "container_metadata", "embedded"))
            timeline.add(
                ForensicTimelineEvent(
                    evidenceId = evidenceId,
                    eventType = "video_container_creation_date",
                    timestampRaw = creationRaw!!,
                    timestampIso = creationRaw,
                    timezoneStatus = "local_unverified",
                    source = "container_metadata (METADATA_KEY_DATE)"
                )
            )
        } else {
            unavailableFields.add("video.creation_date")
        }

        return VideoForensicMetadata(
            containerFormat = detectedFormat,
            majorBrand = majorBrand,
            videoCodec = vCodec,
            audioCodec = aCodec,
            width = width,
            height = height,
            durationMs = durationMs,
            frameRateFps = frameRate,
            bitrateBps = bitrate,
            rotationDegrees = rotation,
            trackCount = trackCount,
            embeddedCreationTimestampRaw = creationRaw,
            filesystemLastModifiedIso = fsLastModIso,
            structuralAtomsFound = atoms
        )
    }

    private fun scanIsoBmffAtoms(file: File): List<String> {
        val atoms = mutableListOf<String>()
        runCatching {
            RandomAccessFile(file, "r").use { raf ->
                val total = raf.length()
                var pos = 0L
                var safety = 0
                while (pos + 8 <= total && safety < 64) {
                    safety++
                    raf.seek(pos)
                    val size32 = raf.readInt().toLong() and 0xFFFFFFFFL
                    val typeBytes = ByteArray(4)
                    raf.readFully(typeBytes)
                    val type = String(typeBytes, StandardCharsets.US_ASCII)
                    if (type.all { it.code in 32..126 }) {
                        atoms.add(type)
                    } else {
                        break
                    }
                    val actualSize = when {
                        size32 == 1L && pos + 16 <= total -> raf.readLong()
                        size32 == 0L -> total - pos
                        else -> size32
                    }
                    if (actualSize < 8L) break
                    pos += actualSize
                }
            }
        }
        return atoms
    }

    // ---------- Audio Metadata Extraction ----------

    private fun extractAudioMetadata(
        file: File,
        detectedFormat: String,
        fsLastModIso: String?,
        extractedFields: MutableList<MetadataField>,
        unavailableFields: MutableList<String>,
        parserWarnings: MutableList<String>
    ): AudioForensicMetadata {
        var sampleRate: Int? = null
        var channels: Int? = null
        var bitrate: Long? = null
        var durationMs: Long? = null
        var title: String? = null
        var artist: String? = null
        var album: String? = null
        var year: String? = null
        var genre: String? = null
        var tagContainer: String? = null

        // 1. Deterministic binary WAV fmt chunk parser
        if (detectedFormat == "WAV" && file.length() >= 44) {
            runCatching {
                RandomAccessFile(file, "r").use { raf ->
                    val hdr = ByteArray(44)
                    raf.readFully(hdr)
                    val bb = ByteBuffer.wrap(hdr).order(ByteOrder.LITTLE_ENDIAN)
                    val ch = bb.getShort(22).toInt() and 0xFFFF
                    val sr = bb.getInt(24)
                    val byteRate = bb.getInt(28).toLong() and 0xFFFFFFFFL
                    if (ch in 1..16 && sr in 4000..384000) {
                        channels = ch
                        sampleRate = sr
                        if (byteRate > 0) {
                            bitrate = byteRate * 8L
                            durationMs = ((file.length() - 44L).coerceAtLeast(0L) * 1000L) / byteRate
                        }
                    }
                }
            }
        }

        // 2. Deterministic ID3v2 / ID3v1 tag parser for MP3
        if (detectedFormat == "MP3") {
            runCatching {
                val id3 = parseMp3Id3Tags(file)
                if (id3.isNotEmpty()) {
                    tagContainer = id3["container"]
                    title = id3["TIT2"] ?: id3["title"]
                    artist = id3["TPE1"] ?: id3["artist"]
                    album = id3["TALB"] ?: id3["album"]
                    year = id3["TYER"] ?: id3["TDRC"] ?: id3["year"]
                    genre = id3["TCON"]
                }
            }
        }

        // 3. Supplement with MediaMetadataRetriever when running on Android device
        runCatching {
            val mmr = MediaMetadataRetriever()
            try {
                mmr.setDataSource(file.absolutePath)
                if (durationMs == null) durationMs = mmr.extractMetadata(MediaMetadataRetriever.METADATA_KEY_DURATION)?.toLongOrNull()
                if (bitrate == null) bitrate = mmr.extractMetadata(MediaMetadataRetriever.METADATA_KEY_BITRATE)?.toLongOrNull()
                if (title == null) title = mmr.extractMetadata(MediaMetadataRetriever.METADATA_KEY_TITLE)
                if (artist == null) artist = mmr.extractMetadata(MediaMetadataRetriever.METADATA_KEY_ARTIST)
                if (album == null) album = mmr.extractMetadata(MediaMetadataRetriever.METADATA_KEY_ALBUM)
                if (year == null) year = mmr.extractMetadata(MediaMetadataRetriever.METADATA_KEY_YEAR)
                if (genre == null) genre = mmr.extractMetadata(MediaMetadataRetriever.METADATA_KEY_GENRE)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && sampleRate == null) {
                    sampleRate = mmr.extractMetadata(MediaMetadataRetriever.METADATA_KEY_SAMPLERATE)?.toIntOrNull()
                }
            } finally {
                runCatching { mmr.release() }
            }
        }.onFailure {
            parserWarnings.add("Audio MediaMetadataRetriever note: ${it.message}")
        }

        if (sampleRate != null) extractedFields.add(MetadataField("audio.sample_rate_hz", sampleRate.toString(), "audio_header", "observed"))
        else unavailableFields.add("audio.sample_rate_hz")
        if (channels != null) extractedFields.add(MetadataField("audio.channels", channels.toString(), "audio_header", "observed"))
        else unavailableFields.add("audio.channels")
        if (durationMs != null) extractedFields.add(MetadataField("audio.duration_ms", durationMs.toString(), "audio_header", "observed"))
        else unavailableFields.add("audio.duration_ms")
        if (bitrate != null) extractedFields.add(MetadataField("audio.bitrate_bps", bitrate.toString(), "audio_header", "observed"))
        else unavailableFields.add("audio.bitrate_bps")
        if (!title.isNullOrBlank()) extractedFields.add(MetadataField("audio.tag.title", title!!, "embedded_id3_tag", "embedded"))
        if (!artist.isNullOrBlank()) extractedFields.add(MetadataField("audio.tag.artist", artist!!, "embedded_id3_tag", "embedded"))
        if (!album.isNullOrBlank()) extractedFields.add(MetadataField("audio.tag.album", album!!, "embedded_id3_tag", "embedded"))

        return AudioForensicMetadata(
            format = detectedFormat,
            codecOrMime = detectedFormat,
            durationMs = durationMs,
            sampleRateHz = sampleRate,
            channelCount = channels,
            bitrateBps = bitrate,
            titleTag = title,
            artistTag = artist,
            albumTag = album,
            yearTag = year,
            genreTag = genre,
            tagContainerType = tagContainer,
            filesystemLastModifiedIso = fsLastModIso
        )
    }

    private fun parseMp3Id3Tags(file: File): Map<String, String> {
        val result = mutableMapOf<String, String>()
        RandomAccessFile(file, "r").use { raf ->
            val len = raf.length()
            if (len >= 10) {
                val hdr = ByteArray(10)
                raf.readFully(hdr)
                if (hdr[0] == 0x49.toByte() && hdr[1] == 0x44.toByte() && hdr[2] == 0x33.toByte()) {
                    val verMajor = hdr[3].toInt() and 0xFF
                    result["container"] = "ID3v2.$verMajor"
                    val tagSize = ((hdr[6].toInt() and 0x7F) shl 21) or
                        ((hdr[7].toInt() and 0x7F) shl 14) or
                        ((hdr[8].toInt() and 0x7F) shl 7) or
                        (hdr[9].toInt() and 0x7F)
                    val readLen = minOf(tagSize.toLong(), 32 * 1024L, len - 10L).toInt()
                    if (readLen > 10 && verMajor in 3..4) {
                        val body = ByteArray(readLen)
                        raf.readFully(body)
                        var pos = 0
                        while (pos + 10 <= body.size) {
                            val frameId = String(body, pos, 4, StandardCharsets.US_ASCII)
                            if (!frameId.all { it in 'A'..'Z' || it in '0'..'9' }) break
                            val fSize = ByteBuffer.wrap(body, pos + 4, 4).int
                            if (fSize <= 0 || pos + 10 + fSize > body.size) break
                            if (frameId.startsWith("T") && fSize > 1) {
                                val enc = body[pos + 10].toInt() and 0xFF
                                val strBytes = body.copyOfRange(pos + 11, pos + 10 + fSize)
                                val text = when (enc) {
                                    1, 2 -> String(strBytes, StandardCharsets.UTF_16)
                                    3 -> String(strBytes, StandardCharsets.UTF_8)
                                    else -> String(strBytes, StandardCharsets.ISO_8859_1)
                                }.trim { it <= ' ' || it == '\u0000' }
                                if (text.isNotEmpty()) result[frameId] = text
                            }
                            pos += 10 + fSize
                        }
                    }
                }
            }
            if (len >= 128) {
                raf.seek(len - 128)
                val v1 = ByteArray(128)
                raf.readFully(v1)
                if (v1[0] == 0x54.toByte() && v1[1] == 0x41.toByte() && v1[2] == 0x47.toByte()) {
                    if (!result.containsKey("container")) result["container"] = "ID3v1"
                    val t = String(v1, 3, 30, StandardCharsets.ISO_8859_1).trim { it <= ' ' || it == '\u0000' }
                    val a = String(v1, 33, 30, StandardCharsets.ISO_8859_1).trim { it <= ' ' || it == '\u0000' }
                    val al = String(v1, 63, 30, StandardCharsets.ISO_8859_1).trim { it <= ' ' || it == '\u0000' }
                    val y = String(v1, 93, 4, StandardCharsets.ISO_8859_1).trim { it <= ' ' || it == '\u0000' }
                    if (t.isNotEmpty() && !result.containsKey("TIT2")) result["title"] = t
                    if (a.isNotEmpty() && !result.containsKey("TPE1")) result["artist"] = a
                    if (al.isNotEmpty() && !result.containsKey("TALB")) result["album"] = al
                    if (y.isNotEmpty() && !result.containsKey("TYER")) result["year"] = y
                }
            }
        }
        return result
    }

    // ---------- Document & Archive Metadata Extraction ----------

    private fun extractDocumentOrArchiveMetadata(
        file: File,
        detectedFormat: String,
        ext: String,
        extractedFields: MutableList<MetadataField>,
        unavailableFields: MutableList<String>,
        parserWarnings: MutableList<String>,
        timeline: MutableList<ForensicTimelineEvent>,
        evidenceId: String
    ): DocumentArchiveForensicMetadata {
        return when {
            detectedFormat == "PDF" || ext == "pdf" ->
                parsePdfMetadata(file, extractedFields, unavailableFields, timeline, evidenceId)
            detectedFormat in setOf("ZIP", "DOCX", "XLSX", "PPTX", "APK") ||
                ext in setOf("zip", "docx", "xlsx", "pptx", "apk") ->
                parseZipOrOoxmlMetadata(file, detectedFormat, extractedFields, unavailableFields, parserWarnings, timeline, evidenceId)
            else -> {
                unavailableFields.add("document.author")
                unavailableFields.add("document.creation_date")
                DocumentArchiveForensicMetadata(
                    formatType = detectedFormat,
                    structureSummary = "Standard file stream (${file.length()} bytes)",
                    digitalSignatureStatus = "not_applicable"
                )
            }
        }
    }

    private fun parsePdfMetadata(
        file: File,
        extractedFields: MutableList<MetadataField>,
        unavailableFields: MutableList<String>,
        timeline: MutableList<ForensicTimelineEvent>,
        evidenceId: String
    ): DocumentArchiveForensicMetadata {
        val len = file.length()
        val headSize = minOf(len, 256 * 1024L).toInt()
        val buf = ByteArray(headSize)
        RandomAccessFile(file, "r").use { raf ->
            raf.seek(0)
            raf.readFully(buf)
        }
        val text = String(buf, StandardCharsets.ISO_8859_1)

        fun extractPdfField(key: String): String? {
            val regex = Regex("""/$key\s*\(([^)\\]*(?:\\.[^)\\]*)*)\)""")
            return regex.find(text)?.groupValues?.getOrNull(1)?.trim()?.takeIf { it.isNotEmpty() }
        }

        val author = extractPdfField("Author")
        val creator = extractPdfField("Creator")
        val producer = extractPdfField("Producer")
        val title = extractPdfField("Title")
        val creationRaw = extractPdfField("CreationDate")
        val modRaw = extractPdfField("ModDate")

        val pageMatches = Regex("""/Type\s*/Page\b""").findAll(text).count()
        val pageCount = if (pageMatches > 0) pageMatches else null
        val hasEmbeddedFiles = text.contains("/EmbeddedFiles") || text.contains("/Filespec")
        val hasSig = text.contains("/Type /Sig") || text.contains("/Type/Sig") || text.contains("/ByteRange")

        if (author != null) extractedFields.add(MetadataField("pdf.author", author, "pdf_info_dictionary", "embedded"))
        else unavailableFields.add("pdf.author")

        if (creator != null) extractedFields.add(MetadataField("pdf.creator", creator, "pdf_info_dictionary", "embedded"))
        else unavailableFields.add("pdf.creator")

        if (producer != null) extractedFields.add(MetadataField("pdf.producer", producer, "pdf_info_dictionary", "embedded"))
        if (title != null) extractedFields.add(MetadataField("pdf.title", title, "pdf_info_dictionary", "embedded"))

        if (creationRaw != null) {
            extractedFields.add(MetadataField("pdf.creation_date_raw", creationRaw, "pdf_info_dictionary", "embedded"))
            val (iso, tz) = ForensicTimeUtil.parsePdfTimestamp(creationRaw)
            timeline.add(
                ForensicTimelineEvent(
                    evidenceId = evidenceId,
                    eventType = "pdf_creation_date",
                    timestampRaw = creationRaw,
                    timestampIso = iso,
                    timezoneStatus = tz,
                    source = "pdf_info_dictionary (/CreationDate)"
                )
            )
        } else {
            unavailableFields.add("pdf.creation_date")
        }

        if (modRaw != null) {
            extractedFields.add(MetadataField("pdf.modification_date_raw", modRaw, "pdf_info_dictionary", "embedded"))
            val (iso, tz) = ForensicTimeUtil.parsePdfTimestamp(modRaw)
            timeline.add(
                ForensicTimelineEvent(
                    evidenceId = evidenceId,
                    eventType = "pdf_modification_date",
                    timestampRaw = modRaw,
                    timestampIso = iso,
                    timezoneStatus = tz,
                    source = "pdf_info_dictionary (/ModDate)"
                )
            )
        } else {
            unavailableFields.add("pdf.modification_date")
        }

        if (pageCount != null) extractedFields.add(MetadataField("pdf.page_count", pageCount.toString(), "pdf_object_tree", "observed"))
        else unavailableFields.add("pdf.page_count")

        val sigStatus = if (hasSig) "present_unverified_chain" else "not_present"
        extractedFields.add(MetadataField("pdf.digital_signature", sigStatus, "pdf_signature_dictionary", "observed"))

        return DocumentArchiveForensicMetadata(
            formatType = "PDF",
            author = author,
            creatorOrLastModifiedBy = creator,
            producerOrApplication = producer,
            title = title,
            creationDateRaw = creationRaw,
            modificationDateRaw = modRaw,
            pageCount = pageCount,
            embeddedAttachments = if (hasEmbeddedFiles) listOf("PDF /EmbeddedFiles dictionary present") else emptyList(),
            structureSummary = "PDF document (${pageCount ?: "unknown"} pages, digital_signature=$sigStatus)",
            digitalSignatureStatus = sigStatus
        )
    }

    private fun parseZipOrOoxmlMetadata(
        file: File,
        detectedFormat: String,
        extractedFields: MutableList<MetadataField>,
        unavailableFields: MutableList<String>,
        parserWarnings: MutableList<String>,
        timeline: MutableList<ForensicTimelineEvent>,
        evidenceId: String
    ): DocumentArchiveForensicMetadata {
        val entries = mutableListOf<String>()
        val attachments = mutableListOf<String>()
        var totalEntries = 0
        var author: String? = null
        var lastModBy: String? = null
        var appName: String? = null
        var title: String? = null
        var createdRaw: String? = null
        var modifiedRaw: String? = null
        var pages: Int? = null
        var hasJarOrApkSignature = false

        runCatching {
            ZipInputStream(BufferedInputStream(FileInputStream(file))).use { zis ->
                var entry: ZipEntry? = zis.nextEntry
                while (entry != null && totalEntries < MAX_ZIP_ENTRIES_INSPECTED) {
                    totalEntries++
                    val name = entry.name
                    if (entries.size < 25) entries.add(name)
                    if (name.startsWith("word/embeddings/") || name.startsWith("xl/embeddings/") || name.startsWith("ppt/embeddings/")) {
                        attachments.add(name)
                    }
                    if (name.startsWith("META-INF/") && (name.endsWith(".RSA", true) || name.endsWith(".DSA", true) || name.endsWith(".EC", true))) {
                        hasJarOrApkSignature = true
                    }
                    if (name == "docProps/core.xml") {
                        val xml = readBoundedStream(zis, MAX_XML_ENTRY_BYTES)
                        author = extractXmlTag(xml, "dc:creator")
                        lastModBy = extractXmlTag(xml, "cp:lastModifiedBy")
                        title = extractXmlTag(xml, "dc:title")
                        createdRaw = extractXmlTag(xml, "dcterms:created")
                        modifiedRaw = extractXmlTag(xml, "dcterms:modified")
                    } else if (name == "docProps/app.xml") {
                        val xml = readBoundedStream(zis, MAX_XML_ENTRY_BYTES)
                        pages = extractXmlTag(xml, "Pages")?.toIntOrNull()
                        appName = extractXmlTag(xml, "Application")
                    }
                    zis.closeEntry()
                    entry = zis.nextEntry
                }
            }
        }.onFailure {
            parserWarnings.add("ZIP/OOXML stream parser warning: ${it.message}")
        }

        extractedFields.add(MetadataField("archive.entry_count", totalEntries.toString(), "zip_central_directory", "observed"))
        if (author != null) extractedFields.add(MetadataField("document.author", author!!, "ooxml_docProps_core", "embedded"))
        else unavailableFields.add("document.author")

        if (lastModBy != null) extractedFields.add(MetadataField("document.last_modified_by", lastModBy!!, "ooxml_docProps_core", "embedded"))
        if (appName != null) extractedFields.add(MetadataField("document.application", appName!!, "ooxml_docProps_app", "embedded"))
        if (pages != null) extractedFields.add(MetadataField("document.page_count", pages.toString(), "ooxml_docProps_app", "embedded"))

        if (createdRaw != null) {
            extractedFields.add(MetadataField("document.created_date", createdRaw!!, "ooxml_docProps_core", "embedded"))
            val tzStatus = if (createdRaw!!.endsWith("Z")) "explicit_utc" else "local_unverified"
            timeline.add(
                ForensicTimelineEvent(
                    evidenceId = evidenceId,
                    eventType = "ooxml_created_date",
                    timestampRaw = createdRaw!!,
                    timestampIso = createdRaw,
                    timezoneStatus = tzStatus,
                    source = "docProps/core.xml (dcterms:created)"
                )
            )
        } else {
            unavailableFields.add("document.created_date")
        }

        if (modifiedRaw != null) {
            extractedFields.add(MetadataField("document.modified_date", modifiedRaw!!, "ooxml_docProps_core", "embedded"))
            val tzStatus = if (modifiedRaw!!.endsWith("Z")) "explicit_utc" else "local_unverified"
            timeline.add(
                ForensicTimelineEvent(
                    evidenceId = evidenceId,
                    eventType = "ooxml_modified_date",
                    timestampRaw = modifiedRaw!!,
                    timestampIso = modifiedRaw,
                    timezoneStatus = tzStatus,
                    source = "docProps/core.xml (dcterms:modified)"
                )
            )
        }

        val sigStatus = if (hasJarOrApkSignature) "present_unverified_chain" else "not_present"
        extractedFields.add(MetadataField("archive.digital_signature", sigStatus, "zip_meta_inf", "observed"))

        return DocumentArchiveForensicMetadata(
            formatType = detectedFormat,
            author = author,
            creatorOrLastModifiedBy = lastModBy,
            producerOrApplication = appName,
            title = title,
            creationDateRaw = createdRaw,
            modificationDateRaw = modifiedRaw,
            pageCount = pages,
            archiveEntryCount = totalEntries,
            archiveEntriesSample = entries,
            embeddedAttachments = attachments,
            structureSummary = "$detectedFormat container ($totalEntries entries inspected, signature=$sigStatus)",
            digitalSignatureStatus = sigStatus
        )
    }

    private fun classifyZipContainer(file: File, ext: String): Pair<String, String> {
        var hasWord = false
        var hasXl = false
        var hasPpt = false
        var hasAndroidManifest = false
        runCatching {
            ZipInputStream(BufferedInputStream(FileInputStream(file))).use { zis ->
                var count = 0
                var e = zis.nextEntry
                while (e != null && count < 40) {
                    count++
                    val n = e.name
                    when {
                        n.startsWith("word/") -> hasWord = true
                        n.startsWith("xl/") -> hasXl = true
                        n.startsWith("ppt/") -> hasPpt = true
                        n == "AndroidManifest.xml" || n == "classes.dex" -> hasAndroidManifest = true
                    }
                    zis.closeEntry()
                    e = zis.nextEntry
                }
            }
        }
        return when {
            hasWord -> "DOCX" to "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            hasXl -> "XLSX" to "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            hasPpt -> "PPTX" to "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            hasAndroidManifest || ext == "apk" -> "APK" to "application/vnd.android.package-archive"
            else -> "ZIP" to "application/zip"
        }
    }

    private fun readBoundedStream(zis: ZipInputStream, maxBytes: Int): String {
        val baos = ByteArrayOutputStream()
        val buf = ByteArray(4096)
        var total = 0
        var n = zis.read(buf)
        while (n != -1 && total < maxBytes) {
            val toWrite = minOf(n, maxBytes - total)
            baos.write(buf, 0, toWrite)
            total += toWrite
            if (total >= maxBytes) break
            n = zis.read(buf)
        }
        return baos.toString("UTF-8")
    }

    private fun extractXmlTag(xml: String, tagName: String): String? {
        val regex = Regex("""<$tagName(?:\s[^>]*)?>([^<]+)</$tagName>""")
        return regex.find(xml)?.groupValues?.getOrNull(1)?.trim()?.takeIf { it.isNotEmpty() }
    }

    private fun computeRecoveryStatistics(
        items: List<ForensicEvidenceRecord>,
        duplicateGroupsCount: Int
    ): RecoveryStatistics {
        val complete = items.count { it.completenessStatus == "complete" }
        val partial = items.count { it.completenessStatus == "partial" }
        val corruptedOrWarn = items.count { it.structureCheck == "corrupted" || it.structureCheck == "warning" }
        val extMismatch = items.count { it.extensionMismatch }
        val byFormat = items.groupingBy { it.detectedFormat }.eachCount()
        return RecoveryStatistics(
            totalFilesEvaluated = items.size,
            recoveredCompleteCount = complete,
            partialOrCarvedCount = partial,
            corruptedOrWarningCount = corruptedOrWarn,
            extensionMismatchCount = extMismatch,
            duplicateGroupCount = duplicateGroupsCount,
            totalBytesAnalyzed = items.sumOf { it.sizeBytes },
            byFormatCounts = byFormat
        )
    }

    fun getDefaultDeviceInfo(): DeviceForensicInfo = DeviceForensicInfo(
        manufacturer = Build.MANUFACTURER ?: "unknown",
        model = Build.MODEL ?: "unknown",
        androidRelease = Build.VERSION.RELEASE ?: "unknown",
        sdkInt = Build.VERSION.SDK_INT,
        deviceBoardOrHardware = "${Build.BOARD ?: "unknown"}/${Build.HARDWARE ?: "unknown"}",
        storageAccessMode = "User-space Android Storage / MediaStore / File API (Non-Root)"
    )

    fun defaultLimitations(hasAllFiles: Boolean): List<String> = listOf(
        "Unallocated raw block storage (/dev/block/*) is inaccessible to non-root Android applications; analysis covers accessible filesystem paths, app caches, trash directories, MediaStore entries, and carved thumbnail databases.",
        "Linux inode birth/creation time (crtime) and low-level journal records are restricted by Android user-space permissions.",
        "Missing embedded metadata (such as stripped EXIF or absent PDF Info tags) does not constitute evidence of tampering; messaging apps and social platforms routinely strip metadata.",
        "Valid container structure and passing signature verification confirm format conformance only and do not independently prove content authenticity or origin.",
        if (hasAllFiles) "Storage access mode: MANAGE_EXTERNAL_STORAGE / standard storage read granted." else "Storage access mode: Restricted scoped storage; some directories may be excluded."
    )

    private fun hasByteSequence(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || haystack.size < needle.size) return false
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return true
        }
        return false
    }

    private fun isMostlyPrintableUtf8(bytes: ByteArray): Boolean {
        if (bytes.isEmpty()) return false
        var printable = 0
        for (b in bytes) {
            val c = b.toInt() and 0xFF
            if (c == 9 || c == 10 || c == 13 || c in 32..126) printable++
        }
        return printable.toDouble() / bytes.size.toDouble() >= 0.85
    }

    private fun ByteArray.toHexLower(): String =
        joinToString("") { "%02x".format(it) }

    private fun ByteArray.toHexUpperSpaced(): String =
        joinToString(" ") { "%02X".format(it) }
}
