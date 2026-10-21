package com.clone.filesrecovery.forensics

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import android.net.Uri
import android.os.Environment
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets
import java.util.Locale

/**
 * Deterministic, offline Forensic Report Generator, External AI Bundle Builder,
 * and SHA-256 Manifest Integrity Verifier for DeepVault (Schema v1.0).
 *
 * Strictly offline: generates structured JSON, Markdown, PDF, CSV, and External AI Bundles
 * on local storage without any AI SDK or external network transmission.
 */
object ForensicReportExporter {

    enum class PromptTemplateType(
        val id: String,
        val title: String,
        val subtitle: String
    ) {
        ANOMALY_REVIEW(
            id = "anomaly_review",
            title = "Anomaly & Tampering Review",
            subtitle = "Identify header/extension mismatches, truncated streams, and metadata anomalies"
        ),
        TIMELINE_RECONSTRUCTION(
            id = "timeline_reconstruction",
            title = "Chronological Timeline Reconstruction",
            subtitle = "Correlate filesystem, EXIF, PDF/OOXML, and recovery timestamps with timezone awareness"
        ),
        METADATA_CONSISTENCY(
            id = "metadata_consistency",
            title = "Cross-Field Metadata Consistency Check",
            subtitle = "Compare embedded camera/author/container tags against filesystem and binary attributes"
        ),
        EXECUTIVE_SUMMARY(
            id = "executive_summary",
            title = "Forensic Executive Summary",
            subtitle = "Generate a concise, evidence-cited briefing for technical and non-technical stakeholders"
        ),
        CORRUPTION_TRIAGE(
            id = "corruption_triage",
            title = "Carving & Corruption Triage",
            subtitle = "Assess partial carves, missing trailer markers, and recovery completeness"
        )
    }

    /**
     * Returns the base directory where DeepVault stores exported forensic reports and bundles.
     */
    fun getReportsBaseDir(context: Context): File {
        val extDocs = runCatching { context.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS) }.getOrNull()
        val base = extDocs ?: File(context.filesDir, "Documents")
        return File(base, "DeepVault_Forensic_Reports").apply { mkdirs() }
    }

    /**
     * Exports a single format (or complete External AI Bundle) for one or more [ForensicCaseReport] parts
     * into [outputRootDir] and generates a verifiable `sha256_manifest.txt`.
     */
    suspend fun exportReports(
        reportParts: List<ForensicCaseReport>,
        formats: Set<ExportFormat> = setOf(
            ExportFormat.JSON,
            ExportFormat.MARKDOWN,
            ExportFormat.PDF,
            ExportFormat.CSV,
            ExportFormat.EXTERNAL_AI_BUNDLE
        ),
        outputRootDir: File
    ): ExportedReportBundle = withContext(Dispatchers.IO) {
        require(reportParts.isNotEmpty()) { "At least one ForensicCaseReport part is required." }
        val primary = reportParts.first()
        val baseReportId = primary.reportId.substringBefore("-P")
        val versionSuffix = "v${primary.reportVersion}"
        val sanitizeTag = if (primary.isSanitized) "_SANITIZED" else ""
        val bundleFolderName = "${primary.caseId}_${baseReportId}_${versionSuffix}${sanitizeTag}"
        val bundleDir = File(outputRootDir, bundleFolderName).apply { mkdirs() }

        val exportedFiles = mutableListOf<ExportedReportFile>()
        val includeBundleExtras = formats.contains(ExportFormat.EXTERNAL_AI_BUNDLE)

        for (part in reportParts) {
            val partSuffix = if (part.totalParts > 1) "_Part${part.partNumber}of${part.totalParts}" else ""

            // 1. JSON Report
            if (formats.contains(ExportFormat.JSON) || includeBundleExtras) {
                val jsonName = if (includeBundleExtras && part.totalParts == 1) {
                    "forensic_report.json"
                } else {
                    "forensic_report_${part.reportId}_${versionSuffix}${partSuffix}.json"
                }
                val jsonFile = File(bundleDir, jsonName)
                val jsonContent = toJsonString(part)
                jsonFile.writeText(jsonContent, StandardCharsets.UTF_8)
                exportedFiles.add(
                    buildExportedFileEntry("json_report", "JSON", jsonFile, part.partNumber, part.totalParts)
                )
            }

            // 2. Markdown Report
            if (formats.contains(ExportFormat.MARKDOWN) || includeBundleExtras) {
                val mdName = if (includeBundleExtras && part.totalParts == 1) {
                    "forensic_report.md"
                } else {
                    "forensic_report_${part.reportId}_${versionSuffix}${partSuffix}.md"
                }
                val mdFile = File(bundleDir, mdName)
                val mdContent = toMarkdownString(part)
                mdFile.writeText(mdContent, StandardCharsets.UTF_8)
                exportedFiles.add(
                    buildExportedFileEntry("markdown_report", "MARKDOWN", mdFile, part.partNumber, part.totalParts)
                )
            }

            // 3. PDF Report
            if (formats.contains(ExportFormat.PDF) || includeBundleExtras) {
                val pdfName = "forensic_report_${part.reportId}_${versionSuffix}${partSuffix}.pdf"
                val pdfFile = File(bundleDir, pdfName)
                writePdfReport(part, pdfFile)
                exportedFiles.add(
                    buildExportedFileEntry("pdf_report", "PDF", pdfFile, part.partNumber, part.totalParts)
                )
            }

            // 4. CSV Exports (Inventory, Metadata Summary, Timeline)
            if (formats.contains(ExportFormat.CSV) || includeBundleExtras) {
                val invName = if (includeBundleExtras && part.totalParts == 1) "evidence_inventory.csv"
                else "evidence_inventory_${part.reportId}${partSuffix}.csv"
                val invFile = File(bundleDir, invName)
                invFile.writeText(toInventoryCsv(part), StandardCharsets.UTF_8)
                exportedFiles.add(
                    buildExportedFileEntry("csv_inventory", "CSV", invFile, part.partNumber, part.totalParts)
                )

                val metaName = if (includeBundleExtras && part.totalParts == 1) "metadata_summary.csv"
                else "metadata_summary_${part.reportId}${partSuffix}.csv"
                val metaFile = File(bundleDir, metaName)
                metaFile.writeText(toMetadataCsv(part), StandardCharsets.UTF_8)
                exportedFiles.add(
                    buildExportedFileEntry("csv_metadata", "CSV", metaFile, part.partNumber, part.totalParts)
                )

                val timeName = if (includeBundleExtras && part.totalParts == 1) "timeline.csv"
                else "timeline_${part.reportId}${partSuffix}.csv"
                val timeFile = File(bundleDir, timeName)
                timeFile.writeText(toTimelineCsv(part), StandardCharsets.UTF_8)
                exportedFiles.add(
                    buildExportedFileEntry("csv_timeline", "CSV", timeFile, part.partNumber, part.totalParts)
                )
            }
        }

        // 5. External AI Bundle dedicated files: case_summary.md and ai_analysis_brief.md
        if (includeBundleExtras) {
            val summaryFile = File(bundleDir, "case_summary.md")
            summaryFile.writeText(buildCaseSummaryMarkdown(reportParts), StandardCharsets.UTF_8)
            exportedFiles.add(
                buildExportedFileEntry("case_summary", "MARKDOWN", summaryFile, 1, reportParts.size)
            )

            val briefFile = File(bundleDir, "ai_analysis_brief.md")
            briefFile.writeText(buildExternalAiBriefMarkdown(primary), StandardCharsets.UTF_8)
            exportedFiles.add(
                buildExportedFileEntry("ai_analysis_brief", "MARKDOWN", briefFile, 1, reportParts.size)
            )
        }

        // 6. Write deterministic sha256_manifest.txt covering all exported report files + evidence items
        val manifestFile = File(bundleDir, "sha256_manifest.txt")
        val manifestText = buildSha256ManifestText(primary, exportedFiles, reportParts.flatMap { it.hashManifest })
        manifestFile.writeText(manifestText, StandardCharsets.UTF_8)
        val manifestEntry = buildExportedFileEntry("sha256_manifest", "TEXT", manifestFile, 1, reportParts.size)

        val allEvidenceIds = reportParts.flatMap { part -> part.evidenceItems.map { it.evidenceId } }.distinct()

        ExportedReportBundle(
            reportId = baseReportId,
            reportVersion = primary.reportVersion,
            caseId = primary.caseId,
            generatedAtIso = primary.generatedAtIso,
            isSanitized = primary.isSanitized,
            redactedFields = primary.redactionSummary,
            files = exportedFiles + manifestEntry,
            manifestFile = manifestFile,
            includedEvidenceIds = allEvidenceIds
        )
    }

    private fun buildExportedFileEntry(
        role: String,
        format: String,
        file: File,
        partNumber: Int,
        totalParts: Int
    ): ExportedReportFile {
        val sha = ForensicAnalyzer.computeSha256Sync(file)
        return ExportedReportFile(
            role = role,
            format = format,
            file = file,
            sha256 = sha,
            sizeBytes = file.length(),
            partNumber = partNumber,
            totalParts = totalParts
        )
    }

    // ---------- 1. JSON Report Serialization (Schema v1.0) ----------

    fun toJsonString(report: ForensicCaseReport): String {
        val root = JSONObject()
        root.put("schema_version", report.schemaVersion)
        root.put("report_id", report.reportId)
        root.put("report_version", report.reportVersion)
        root.put("report_type", report.reportType)
        root.put("generated_at_utc", report.generatedAtIso)
        root.put("app_name", report.appName)
        root.put("app_version", report.appVersion)
        root.put("case_id", report.caseId)
        root.put("case_created_at_utc", report.caseCreatedAtIso)
        root.put("scan_session_id", report.scanSessionId)
        root.put("acquisition_method", report.acquisitionMethod)
        root.put("part_number", report.partNumber)
        root.put("total_parts", report.totalParts)
        root.put("total_evidence_in_case", report.totalEvidenceInCase)

        // Privacy & Sanitization metadata
        val privacyObj = JSONObject().apply {
            put("is_sanitized", report.isSanitized)
            put("include_gps", report.privacyOptions.includeGps)
            put("redact_sensitive_paths", report.privacyOptions.redactSensitivePaths)
            put("exclude_personal_filenames", report.privacyOptions.excludePersonalFilenames)
            put("excluded_evidence_count", report.privacyOptions.excludedEvidenceIds.size)
            put("redaction_summary", JSONArray(report.redactionSummary))
        }
        root.put("privacy_and_redaction", privacyObj)

        // Device & Environment Info
        val devObj = JSONObject().apply {
            put("manufacturer", report.deviceInfo.manufacturer)
            put("model", report.deviceInfo.model)
            put("android_release", report.deviceInfo.androidRelease)
            put("sdk_int", report.deviceInfo.sdkInt)
            put("board_hardware", report.deviceInfo.deviceBoardOrHardware)
            put("storage_access_mode", report.deviceInfo.storageAccessMode)
            put("parser_suite_version", report.deviceInfo.parserSuiteVersion)
        }
        root.put("device_info", devObj)

        // Recovery Statistics
        val stats = report.recoveryStats
        val statsObj = JSONObject().apply {
            put("total_files_evaluated", stats.totalFilesEvaluated)
            put("recovered_complete_count", stats.recoveredCompleteCount)
            put("partial_or_carved_count", stats.partialOrCarvedCount)
            put("corrupted_or_warning_count", stats.corruptedOrWarningCount)
            put("extension_mismatch_count", stats.extensionMismatchCount)
            put("duplicate_group_count", stats.duplicateGroupCount)
            put("total_bytes_analyzed", stats.totalBytesAnalyzed)
            val byFmt = JSONObject()
            stats.byFormatCounts.forEach { (k, v) -> byFmt.put(k, v) }
            put("by_format_counts", byFmt)
        }
        root.put("recovery_statistics", statsObj)

        // Hash Manifest
        val manifestArr = JSONArray()
        report.hashManifest.forEach { m ->
            manifestArr.put(
                JSONObject().apply {
                    put("evidence_id", m.evidenceId)
                    put("filename", m.filename)
                    put("size_bytes", m.sizeBytes)
                    put("sha256", m.sha256)
                    put("md5", m.md5 ?: JSONObject.NULL)
                    put("sha1", m.sha1 ?: JSONObject.NULL)
                    put("hash_target", m.hashTarget)
                    put("calculated_at_utc", m.calculatedAtIso)
                }
            )
        }
        root.put("hash_manifest", manifestArr)

        // Evidence Items
        val evidenceArr = JSONArray()
        report.evidenceItems.forEach { item ->
            evidenceArr.put(serializeEvidenceItemJson(item))
        }
        root.put("evidence_items", evidenceArr)

        // Duplicate Groups
        val dupArr = JSONArray()
        report.duplicateGroups.forEach { dg ->
            dupArr.put(
                JSONObject().apply {
                    put("group_id", dg.groupId)
                    put("match_basis", dg.matchBasis)
                    put("hash_value", dg.hashValue)
                    put("evidence_ids", JSONArray(dg.evidenceIds))
                    put("filenames", JSONArray(dg.filenames))
                    put("total_bytes", dg.totalBytes)
                }
            )
        }
        root.put("duplicate_groups", dupArr)

        // Chronological Timeline
        val timeArr = JSONArray()
        report.timeline.forEach { ev ->
            timeArr.put(
                JSONObject().apply {
                    put("evidence_id", ev.evidenceId)
                    put("event_type", ev.eventType)
                    put("timestamp_raw", ev.timestampRaw)
                    put("timestamp_iso", ev.timestampIso ?: JSONObject.NULL)
                    put("timezone_status", ev.timezoneStatus)
                    put("source", ev.source)
                    put("notes", ev.notes)
                }
            )
        }
        root.put("timeline", timeArr)

        // Rule-Based Findings
        val findArr = JSONArray()
        report.findings.forEach { f ->
            findArr.put(
                JSONObject().apply {
                    put("finding_id", f.findingId)
                    put("evidence_id", f.evidenceId)
                    put("severity", f.severity)
                    put("category", f.category)
                    put("title", f.title)
                    put("description", f.description)
                    put("observation_basis", f.observationBasis)
                }
            )
        }
        root.put("findings", findArr)

        root.put("limitations", JSONArray(report.limitations))
        root.put("errors", JSONArray(report.errors))
        root.put(
            "integrity_disclaimer",
            "A report hash proves the byte-level integrity of the exported report files being compared; it does not independently prove the accuracy of the underlying forensic conclusions."
        )

        return root.toString(2)
    }

    private fun serializeEvidenceItemJson(item: ForensicEvidenceRecord): JSONObject {
        val obj = JSONObject()
        obj.put("evidence_id", item.evidenceId)
        obj.put("original_filename", item.originalFilename ?: JSONObject.NULL)
        obj.put("current_filename", item.currentFilename)
        obj.put("size_bytes", item.sizeBytes)
        obj.put("extension", item.extension)
        obj.put("detected_mime_type", item.detectedMimeType)
        obj.put("detected_format", item.detectedFormat)
        obj.put("signature_hex", item.signatureHex)
        obj.put("magic_description", item.magicDescription)
        obj.put("source_location", item.sourceLocation ?: JSONObject.NULL)
        obj.put("recovered_output_path", item.recoveredOutputPath ?: JSONObject.NULL)
        obj.put("recovery_status", item.recoveryStatus)
        obj.put("recovery_method", item.recoveryMethod)
        obj.put("recovery_timestamp_utc", item.recoveryTimestampIso ?: JSONObject.NULL)
        obj.put("scan_session_id", item.scanSessionId)
        obj.put("completeness_status", item.completenessStatus)
        obj.put("structure_check", item.structureCheck)
        obj.put("structure_detail", item.structureDetail)
        obj.put("signature_check", item.signatureCheck)
        obj.put("extension_mismatch", item.extensionMismatch)
        obj.put("extension_mismatch_detail", item.extensionMismatchDetail ?: JSONObject.NULL)
        obj.put("corruption_indicators", JSONArray(item.corruptionIndicators))

        // Cryptographic Hashes
        val hashesObj = JSONObject().apply {
            put("sha256", item.sha256)
            put("md5", item.md5 ?: JSONObject.NULL)
            put("sha1", item.sha1 ?: JSONObject.NULL)
            put("calculated_at_utc", item.hashCalculatedAtIso)
            put("hash_target", item.hashTarget)
            put("reference_hash", item.referenceHash ?: JSONObject.NULL)
            put("reference_hash_match", item.referenceHashMatch)
        }
        obj.put("hashes", hashesObj)

        // Metadata fields with explicit provenance
        val fieldsArr = JSONArray()
        item.extractedFields.forEach { mf ->
            fieldsArr.put(
                JSONObject().apply {
                    put("key", mf.key)
                    put("value", mf.value)
                    put("source", mf.source)
                    put("value_category", mf.valueCategory)
                }
            )
        }
        val metaObj = JSONObject().apply {
            put("metadata_source_summary", item.metadataSourceSummary)
            put("extracted_fields", fieldsArr)
            put("unavailable_fields", JSONArray(item.unavailableFields))
            put("parser_warnings", JSONArray(item.parserWarnings))
            put("metadata_inconsistencies", JSONArray(item.metadataInconsistencies))
        }
        obj.put("metadata", metaObj)

        // Domain-specific metadata blocks
        item.imageMetadata?.let { img ->
            obj.put(
                "image_metadata",
                JSONObject().apply {
                    put("width", img.width ?: JSONObject.NULL)
                    put("height", img.height ?: JSONObject.NULL)
                    put("detected_format", img.detectedFormat ?: JSONObject.NULL)
                    put("color_profile_or_config", img.colorProfileOrConfig ?: JSONObject.NULL)
                    put("camera_make", img.cameraMake ?: JSONObject.NULL)
                    put("camera_model", img.cameraModel ?: JSONObject.NULL)
                    put("capture_timestamp_raw", img.captureTimestampRaw ?: JSONObject.NULL)
                    put("subsec_time_original", img.subSecTimeOriginal ?: JSONObject.NULL)
                    put("orientation", img.orientation ?: JSONObject.NULL)
                    put("software", img.software ?: JSONObject.NULL)
                    put("has_embedded_thumbnail", img.hasEmbeddedThumbnail)
                    put("thumbnail_width", img.thumbnailWidth ?: JSONObject.NULL)
                    put("thumbnail_height", img.thumbnailHeight ?: JSONObject.NULL)
                    put("compression_info", img.compressionInfo ?: JSONObject.NULL)
                    put("exposure_time", img.exposureTime ?: JSONObject.NULL)
                    put("f_number", img.fNumber ?: JSONObject.NULL)
                    put("iso_speed", img.isoSpeed ?: JSONObject.NULL)
                    put("focal_length", img.focalLength ?: JSONObject.NULL)
                    put("filesystem_last_modified_utc", img.filesystemLastModifiedIso ?: JSONObject.NULL)
                    if (img.gps != null) {
                        put(
                            "gps",
                            JSONObject().apply {
                                put("latitude", img.gps.latitude)
                                put("longitude", img.gps.longitude)
                                put("altitude_meters", img.gps.altitudeMeters ?: JSONObject.NULL)
                                put("gps_timestamp_utc", img.gps.gpsTimestampUtc ?: JSONObject.NULL)
                                put("source", img.gps.source)
                            }
                        )
                    } else {
                        put("gps", JSONObject.NULL)
                    }
                }
            )
        }

        item.videoMetadata?.let { vid ->
            obj.put(
                "video_metadata",
                JSONObject().apply {
                    put("container_format", vid.containerFormat ?: JSONObject.NULL)
                    put("major_brand", vid.majorBrand ?: JSONObject.NULL)
                    put("video_codec", vid.videoCodec ?: JSONObject.NULL)
                    put("audio_codec", vid.audioCodec ?: JSONObject.NULL)
                    put("width", vid.width ?: JSONObject.NULL)
                    put("height", vid.height ?: JSONObject.NULL)
                    put("duration_ms", vid.durationMs ?: JSONObject.NULL)
                    put("frame_rate_fps", vid.frameRateFps ?: JSONObject.NULL)
                    put("bitrate_bps", vid.bitrateBps ?: JSONObject.NULL)
                    put("rotation_degrees", vid.rotationDegrees ?: JSONObject.NULL)
                    put("track_count", vid.trackCount ?: JSONObject.NULL)
                    put("embedded_creation_timestamp_raw", vid.embeddedCreationTimestampRaw ?: JSONObject.NULL)
                    put("filesystem_last_modified_utc", vid.filesystemLastModifiedIso ?: JSONObject.NULL)
                    put("structural_atoms_found", JSONArray(vid.structuralAtomsFound))
                }
            )
        }

        item.audioMetadata?.let { aud ->
            obj.put(
                "audio_metadata",
                JSONObject().apply {
                    put("format", aud.format ?: JSONObject.NULL)
                    put("codec_or_mime", aud.codecOrMime ?: JSONObject.NULL)
                    put("duration_ms", aud.durationMs ?: JSONObject.NULL)
                    put("sample_rate_hz", aud.sampleRateHz ?: JSONObject.NULL)
                    put("channel_count", aud.channelCount ?: JSONObject.NULL)
                    put("bitrate_bps", aud.bitrateBps ?: JSONObject.NULL)
                    put("title_tag", aud.titleTag ?: JSONObject.NULL)
                    put("artist_tag", aud.artistTag ?: JSONObject.NULL)
                    put("album_tag", aud.albumTag ?: JSONObject.NULL)
                    put("year_tag", aud.yearTag ?: JSONObject.NULL)
                    put("genre_tag", aud.genreTag ?: JSONObject.NULL)
                    put("tag_container_type", aud.tagContainerType ?: JSONObject.NULL)
                    put("filesystem_last_modified_utc", aud.filesystemLastModifiedIso ?: JSONObject.NULL)
                }
            )
        }

        item.documentMetadata?.let { doc ->
            obj.put(
                "document_metadata",
                JSONObject().apply {
                    put("format_type", doc.formatType ?: JSONObject.NULL)
                    put("author", doc.author ?: JSONObject.NULL)
                    put("creator_or_last_modified_by", doc.creatorOrLastModifiedBy ?: JSONObject.NULL)
                    put("producer_or_application", doc.producerOrApplication ?: JSONObject.NULL)
                    put("title", doc.title ?: JSONObject.NULL)
                    put("creation_date_raw", doc.creationDateRaw ?: JSONObject.NULL)
                    put("modification_date_raw", doc.modificationDateRaw ?: JSONObject.NULL)
                    put("page_count", doc.pageCount ?: JSONObject.NULL)
                    put("archive_entry_count", doc.archiveEntryCount ?: JSONObject.NULL)
                    put("archive_entries_sample", JSONArray(doc.archiveEntriesSample))
                    put("embedded_attachments", JSONArray(doc.embeddedAttachments))
                    put("structure_summary", doc.structureSummary ?: JSONObject.NULL)
                    put("digital_signature_status", doc.digitalSignatureStatus)
                }
            )
        }

        obj.put("duplicate_group_id", item.duplicateGroupId ?: JSONObject.NULL)
        obj.put("similar_file_evidence_ids", JSONArray(item.similarFileEvidenceIds))
        obj.put("is_redacted", item.isRedacted)
        obj.put("redacted_field_names", JSONArray(item.redactedFieldNames))
        obj.put("limitations", JSONArray(item.limitations))
        obj.put("errors", JSONArray(item.errors))
        return obj
    }

    // ---------- 2. Markdown Report Generation ----------

    fun toMarkdownString(report: ForensicCaseReport): String {
        val sb = StringBuilder()
        sb.appendLine("# DeepVault Forensic Analysis Report")
        sb.appendLine()
        sb.appendLine("## 1. Case & Report Identification")
        sb.appendLine("| Field | Value |")
        sb.appendLine("| :--- | :--- |")
        sb.appendLine("| **Report ID** | `${report.reportId}` (Version ${report.reportVersion}, Schema v${report.schemaVersion}) |")
        sb.appendLine("| **Report Scope** | `${report.reportType}` (Part ${report.partNumber} of ${report.totalParts}; ${report.evidenceItems.size} of ${report.totalEvidenceInCase} items) |")
        sb.appendLine("| **Case ID** | `${report.caseId}` |")
        sb.appendLine("| **Scan Session ID** | `${report.scanSessionId}` |")
        sb.appendLine("| **Generated At (UTC)** | `${report.generatedAtIso}` |")
        sb.appendLine("| **Application & Parser Suite** | `${report.appName} v${report.appVersion}` — `${report.deviceInfo.parserSuiteVersion}` |")
        sb.appendLine("| **Device Environment** | `${report.deviceInfo.manufacturer} ${report.deviceInfo.model}` (Android ${report.deviceInfo.androidRelease}, SDK ${report.deviceInfo.sdkInt}) |")
        sb.appendLine("| **Storage Access Mode** | `${report.deviceInfo.storageAccessMode}` |")
        sb.appendLine("| **Acquisition Method** | ${report.acquisitionMethod} |")
        sb.appendLine("| **Sanitized / Redacted** | `${report.isSanitized}` ${if (report.redactionSummary.isNotEmpty()) "(${report.redactionSummary.joinToString(", ")})" else "(Unredacted full report)"} |")
        sb.appendLine()

        val s = report.recoveryStats
        sb.appendLine("## 2. Recovery & Structural Integrity Statistics")
        sb.appendLine("- **Total Evidence Items Analyzed:** ${s.totalFilesEvaluated} (${s.totalBytesAnalyzed} bytes)")
        sb.appendLine("- **Complete Structural Verification:** ${s.recoveredCompleteCount}")
        sb.appendLine("- **Partial / Carved Candidates:** ${s.partialOrCarvedCount}")
        sb.appendLine("- **Corrupted / Structural Warnings:** ${s.corruptedOrWarningCount}")
        sb.appendLine("- **Extension Mismatches Detected:** ${s.extensionMismatchCount}")
        sb.appendLine("- **Exact Duplicate Clusters:** ${s.duplicateGroupCount}")
        if (s.byFormatCounts.isNotEmpty()) {
            sb.appendLine("- **Detected Format Distribution:** ${s.byFormatCounts.entries.joinToString(", ") { "${it.key}: ${it.value}" }}")
        }
        sb.appendLine()

        sb.appendLine("## 3. Cryptographic Hash Manifest")
        sb.appendLine("| Evidence ID | Filename | Size (Bytes) | SHA-256 | MD5 | Hash Target |")
        sb.appendLine("| :--- | :--- | ---: | :--- | :--- | :--- |")
        report.hashManifest.forEach { m ->
            sb.appendLine("| `${m.evidenceId}` | `${escapeMd(m.filename)}` | ${m.sizeBytes} | `${m.sha256}` | `${m.md5 ?: "n/a"}` | `${m.hashTarget}` |")
        }
        sb.appendLine()

        sb.appendLine("## 4. Detailed Evidence Examination")
        report.evidenceItems.forEach { item ->
            sb.appendLine("### Evidence Item `${item.evidenceId}` — `${escapeMd(item.currentFilename)}`")
            sb.appendLine("- **Original Filename:** `${item.originalFilename ?: "unavailable"}`")
            sb.appendLine("- **Current Filename:** `${item.currentFilename}`")
            sb.appendLine("- **File Size:** `${item.sizeBytes}` bytes")
            sb.appendLine("- **Detected Format & MIME:** `${item.detectedFormat}` (`${item.detectedMimeType}`)")
            sb.appendLine("- **Binary Signature (First 16 Bytes):** `${item.signatureHex.ifBlank { "empty" }}` (${item.magicDescription})")
            sb.appendLine("- **Signature & Extension Check:** `${item.signatureCheck}` | Extension Mismatch: `${item.extensionMismatch}` ${item.extensionMismatchDetail?.let { "— $it" } ?: ""}")
            sb.appendLine("- **Structural Validation:** `${item.structureCheck}` — ${item.structureDetail}")
            sb.appendLine("- **Recovery Status & Method:** `${item.recoveryStatus}` via `${item.recoveryMethod}` (Completeness: `${item.completenessStatus}`)")
            sb.appendLine("- **Source Path:** `${item.sourceLocation ?: "unavailable"}`")
            if (item.recoveredOutputPath != null) {
                sb.appendLine("- **Recovered Output Path:** `${item.recoveredOutputPath}`")
            }
            sb.appendLine("- **Cryptographic Hashes (${item.hashTarget}):**")
            sb.appendLine("  - `SHA-256`: `${item.sha256}`")
            sb.appendLine("  - `MD5`: `${item.md5 ?: "unavailable"}`")
            sb.appendLine("  - `SHA-1`: `${item.sha1 ?: "unavailable"}`")
            if (item.referenceHash != null) {
                sb.appendLine("  - `Reference Hash Comparison`: `${item.referenceHashMatch}` (Reference: `${item.referenceHash}`)")
            }
            if (item.corruptionIndicators.isNotEmpty()) {
                sb.appendLine("- **Corruption / Truncation Indicators:** `${item.corruptionIndicators.joinToString(", ")}`")
            }
            if (item.duplicateGroupId != null) {
                sb.appendLine("- **Duplicate Cluster:** `${item.duplicateGroupId}` (Shared with: `${item.similarFileEvidenceIds.joinToString(", ")}`)")
            }

            if (item.extractedFields.isNotEmpty()) {
                sb.appendLine()
                sb.appendLine("#### Extracted Metadata Fields (`${item.evidenceId}`)")
                sb.appendLine("| Field Key | Value | Provenance Source | Category |")
                sb.appendLine("| :--- | :--- | :--- | :--- |")
                item.extractedFields.forEach { mf ->
                    sb.appendLine("| `${mf.key}` | `${escapeMd(mf.value)}` | `${mf.source}` | `${mf.valueCategory}` |")
                }
            }

            if (item.metadataInconsistencies.isNotEmpty()) {
                sb.appendLine()
                sb.appendLine("#### Observed Metadata Inconsistencies (`${item.evidenceId}`)")
                item.metadataInconsistencies.forEach { inc ->
                    sb.appendLine("- [RULE-BASED OBSERVATION] $inc")
                }
            }

            if (item.unavailableFields.isNotEmpty()) {
                sb.appendLine()
                sb.appendLine("- **Unavailable / Absent Fields:** `${item.unavailableFields.joinToString(", ")}`")
            }
            if (item.parserWarnings.isNotEmpty()) {
                sb.appendLine("- **Parser Warnings:** `${item.parserWarnings.joinToString("; ")}`")
            }
            sb.appendLine()
        }

        sb.appendLine("## 5. Chronological Forensic Timeline")
        if (report.timeline.isEmpty()) {
            sb.appendLine("_No timestamp events were available across the evaluated evidence items._")
        } else {
            sb.appendLine("| Evidence ID | Event Type | Normalized Timestamp | Timezone Status | Provenance Source | Notes |")
            sb.appendLine("| :--- | :--- | :--- | :--- | :--- | :--- |")
            report.timeline.forEach { ev ->
                sb.appendLine("| `${ev.evidenceId}` | `${ev.eventType}` | `${ev.timestampIso ?: ev.timestampRaw}` | `${ev.timezoneStatus}` | `${ev.source}` | ${escapeMd(ev.notes)} |")
            }
        }
        sb.appendLine()

        sb.appendLine("## 6. Rule-Based Forensic Findings")
        if (report.findings.isEmpty()) {
            sb.appendLine("_No structural warnings or rule-based anomalies triggered._")
        } else {
            report.findings.forEach { f ->
                sb.appendLine("- **[${f.severity.uppercase(Locale.US)}] `${f.findingId}` (`${f.evidenceId}` — ${f.category}):** **${f.title}** — ${f.description} _(Basis: `${f.observationBasis}`)_")
            }
        }
        sb.appendLine()

        sb.appendLine("## 7. Forensic Scope & Technical Limitations")
        report.limitations.forEach { lim ->
            sb.appendLine("- $lim")
        }
        sb.appendLine("- **Report Hash Disclaimer:** A report hash proves the byte-level integrity of the exported report files being compared; it does not independently prove the accuracy of the underlying forensic conclusions.")
        sb.appendLine()

        sb.appendLine("## 8. Recommended External AI Analysis Prompts")
        sb.appendLine("Users may copy any of the following deterministic prompts and upload this report (`forensic_report.json` or `forensic_report.md`) to an external AI service of their choice:")
        sb.appendLine()
        PromptTemplateType.entries.forEach { tmpl ->
            sb.appendLine("### ${tmpl.title}")
            sb.appendLine("```text")
            sb.appendLine(buildPromptText(tmpl, report, includeExcerpt = false))
            sb.appendLine("```")
            sb.appendLine()
        }

        return sb.toString()
    }

    // ---------- 3. Printable PDF Report Generation ----------

    fun writePdfReport(report: ForensicCaseReport, outFile: File) {
        val wroteAndroidPdf = runCatching {
            val pdfDoc = PdfDocument()
            try {
                val pageWidth = 595 // A4 width in points
                val pageHeight = 842 // A4 height in points
                val margin = 36f
                val maxWidth = pageWidth - (margin * 2).toInt()

                val lines = buildPdfTextLines(report, maxCharsPerLine = 88)
                val linesPerPage = 48
                val chunks = if (lines.isEmpty()) listOf(listOf("DeepVault Forensic Report")) else lines.chunked(linesPerPage)

                val titlePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                    color = Color.rgb(30, 41, 59)
                    textSize = 13f
                    typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
                }
                val bodyPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                    color = Color.rgb(15, 23, 42)
                    textSize = 9.2f
                    typeface = Typeface.create(Typeface.MONOSPACE, Typeface.NORMAL)
                }
                val headerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                    color = Color.rgb(79, 70, 229)
                    textSize = 10.5f
                    typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
                }
                val footerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                    color = Color.rgb(100, 116, 139)
                    textSize = 8.5f
                    typeface = Typeface.create(Typeface.SANS_SERIF, Typeface.NORMAL)
                }

                chunks.forEachIndexed { pageIdx, pageLines ->
                    val pageInfo = PdfDocument.PageInfo.Builder(pageWidth, pageHeight, pageIdx + 1).create()
                    val page = pdfDoc.startPage(pageInfo)
                    val canvas: Canvas = page.canvas

                    // Top banner line
                    canvas.drawText(
                        "DEEPVAULT FORENSIC REPORT | Case: ${report.caseId} | Report: ${report.reportId} v${report.reportVersion}",
                        margin,
                        margin,
                        titlePaint
                    )
                    var y = margin + 22f
                    for (line in pageLines) {
                        val paint = if (line.startsWith("===") || line.startsWith("--- [")) headerPaint else bodyPaint
                        canvas.drawText(line.take(96), margin, y, paint)
                        y += 15f
                    }

                    // Footer with page number and integrity note
                    canvas.drawText(
                        "Page ${pageIdx + 1} of ${chunks.size}  |  Schema v${report.schemaVersion}  |  Offline Deterministic Analysis (No AI SDK)",
                        margin,
                        pageHeight - 24f,
                        footerPaint
                    )
                    pdfDoc.finishPage(page)
                }

                FileOutputStream(outFile).use { fos ->
                    pdfDoc.writeTo(fos)
                }
                outFile.exists() && outFile.length() > 64L
            } finally {
                runCatching { pdfDoc.close() }
            }
        }.getOrDefault(false)

        if (!wroteAndroidPdf) {
            writeFallbackValidPdf(report, outFile)
        }
    }

    private fun buildPdfTextLines(report: ForensicCaseReport, maxCharsPerLine: Int): List<String> {
        val rawLines = mutableListOf<String>()
        rawLines.add("=== 1. CASE & ACQUISITION SUMMARY ===")
        rawLines.add("Report ID: ${report.reportId} (v${report.reportVersion}, Schema v${report.schemaVersion})")
        rawLines.add("Case ID: ${report.caseId} | Session: ${report.scanSessionId}")
        rawLines.add("Generated (UTC): ${report.generatedAtIso}")
        rawLines.add("Device: ${report.deviceInfo.manufacturer} ${report.deviceInfo.model} (Android ${report.deviceInfo.androidRelease}, SDK ${report.deviceInfo.sdkInt})")
        rawLines.add("Acquisition: ${report.acquisitionMethod}")
        rawLines.add("Sanitized: ${report.isSanitized} ${if (report.redactionSummary.isNotEmpty()) report.redactionSummary.joinToString(", ") else ""}")
        rawLines.add("")

        val st = report.recoveryStats
        rawLines.add("=== 2. RECOVERY STATISTICS ===")
        rawLines.add("Files Evaluated: ${st.totalFilesEvaluated} (${st.totalBytesAnalyzed} bytes)")
        rawLines.add("Complete: ${st.recoveredCompleteCount} | Partial/Carved: ${st.partialOrCarvedCount} | Corrupted/Warning: ${st.corruptedOrWarningCount}")
        rawLines.add("Extension Mismatches: ${st.extensionMismatchCount} | Duplicate Groups: ${st.duplicateGroupCount}")
        rawLines.add("")

        rawLines.add("=== 3. CRYPTOGRAPHIC HASH MANIFEST ===")
        report.hashManifest.forEach { m ->
            rawLines.add("${m.evidenceId} | ${m.filename} (${m.sizeBytes} B) [${m.hashTarget}]")
            rawLines.add("  SHA-256: ${m.sha256}")
            if (m.md5 != null) rawLines.add("  MD5: ${m.md5} | SHA-1: ${m.sha1 ?: "n/a"}")
        }
        rawLines.add("")

        rawLines.add("=== 4. EVIDENCE RECORDS ===")
        report.evidenceItems.forEach { item ->
            rawLines.add("--- [${item.evidenceId}] ${item.currentFilename} ---")
            rawLines.add("Format: ${item.detectedFormat} (${item.detectedMimeType}) | Size: ${item.sizeBytes} B")
            rawLines.add("Magic Hex: ${item.signatureHex} (${item.magicDescription})")
            rawLines.add("Structure: ${item.structureCheck} - ${item.structureDetail}")
            rawLines.add("Recovery: ${item.recoveryStatus} via ${item.recoveryMethod} (Completeness: ${item.completenessStatus})")
            rawLines.add("SHA-256: ${item.sha256}")
            item.extractedFields.take(12).forEach { mf ->
                rawLines.add("  [${mf.valueCategory}/${mf.source}] ${mf.key} = ${mf.value}")
            }
            if (item.unavailableFields.isNotEmpty()) {
                rawLines.add("  Unavailable: ${item.unavailableFields.joinToString(", ")}")
            }
            rawLines.add("")
        }

        rawLines.add("=== 5. TIMELINE & FINDINGS ===")
        report.timeline.forEach { ev ->
            rawLines.add("${ev.timestampIso ?: ev.timestampRaw} [${ev.timezoneStatus}] ${ev.evidenceId} ${ev.eventType} (${ev.source})")
        }
        report.findings.forEach { f ->
            rawLines.add("[${f.severity.uppercase(Locale.US)}] ${f.findingId}: ${f.title} - ${f.description}")
        }
        rawLines.add("")
        rawLines.add("=== 6. LIMITATIONS & DISCLAIMER ===")
        report.limitations.forEach { rawLines.add("* $it") }
        rawLines.add("* A report hash proves the byte-level integrity of the exported report files being compared; it does not independently prove the accuracy of the underlying forensic conclusions.")

        // Wrap long lines cleanly
        val wrapped = mutableListOf<String>()
        for (line in rawLines) {
            if (line.length <= maxCharsPerLine) {
                wrapped.add(line)
            } else {
                var idx = 0
                while (idx < line.length) {
                    val end = minOf(idx + maxCharsPerLine, line.length)
                    wrapped.add(if (idx == 0) line.substring(idx, end) else "  " + line.substring(idx, end))
                    idx = end
                }
            }
        }
        return wrapped
    }

    /**
     * Minimal standards-compliant PDF 1.4 writer used if Android's native PdfDocument canvas
     * returns 0 bytes in headless unit-test environments.
     */
    private fun writeFallbackValidPdf(report: ForensicCaseReport, outFile: File) {
        val textLines = buildPdfTextLines(report, 82).take(55)
        val contentBuilder = StringBuilder("BT /F1 9 Tf 36 800 Td 12 TL\n")
        for (l in textLines) {
            val escaped = l.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            contentBuilder.append("($escaped) Tj T*\n")
        }
        contentBuilder.append("ET\n")
        val streamBytes = contentBuilder.toString().toByteArray(StandardCharsets.US_ASCII)

        val pdf = buildString {
            append("%PDF-1.4\n")
            append("1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
            append("2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n")
            append("3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj\n")
            append("4 0 obj << /Length ${streamBytes.size} >>\nstream\n")
            append(String(streamBytes, StandardCharsets.US_ASCII))
            append("endstream\nendobj\n")
            append("5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Courier >> endobj\n")
            append("trailer << /Root 1 0 R /Size 6 >>\n%%EOF\n")
        }
        outFile.writeBytes(pdf.toByteArray(StandardCharsets.US_ASCII))
    }

    // ---------- 4. CSV Exports (Inventory, Metadata, Timeline) ----------

    fun toInventoryCsv(report: ForensicCaseReport): String {
        val sb = StringBuilder()
        sb.appendLine("evidence_id,original_filename,current_filename,size_bytes,extension,detected_format,detected_mime_type,signature_hex,signature_check,extension_mismatch,structure_check,completeness_status,recovery_status,recovery_method,sha256,md5,sha1,hash_target,duplicate_group_id,source_location")
        report.evidenceItems.forEach { item ->
            sb.appendLine(
                listOf(
                    item.evidenceId,
                    item.originalFilename ?: "",
                    item.currentFilename,
                    item.sizeBytes.toString(),
                    item.extension,
                    item.detectedFormat,
                    item.detectedMimeType,
                    item.signatureHex,
                    item.signatureCheck,
                    item.extensionMismatch.toString(),
                    item.structureCheck,
                    item.completenessStatus,
                    item.recoveryStatus,
                    item.recoveryMethod,
                    item.sha256,
                    item.md5 ?: "",
                    item.sha1 ?: "",
                    item.hashTarget,
                    item.duplicateGroupId ?: "",
                    item.sourceLocation ?: ""
                ).joinToString(",") { csvEscape(it) }
            )
        }
        return sb.toString()
    }

    fun toMetadataCsv(report: ForensicCaseReport): String {
        val sb = StringBuilder()
        sb.appendLine("evidence_id,filename,field_key,field_value,provenance_source,value_category")
        report.evidenceItems.forEach { item ->
            item.extractedFields.forEach { mf ->
                sb.appendLine(
                    listOf(
                        item.evidenceId,
                        item.currentFilename,
                        mf.key,
                        mf.value,
                        mf.source,
                        mf.valueCategory
                    ).joinToString(",") { csvEscape(it) }
                )
            }
        }
        return sb.toString()
    }

    fun toTimelineCsv(report: ForensicCaseReport): String {
        val sb = StringBuilder()
        sb.appendLine("evidence_id,event_type,timestamp_raw,timestamp_iso,timezone_status,provenance_source,notes")
        report.timeline.forEach { ev ->
            sb.appendLine(
                listOf(
                    ev.evidenceId,
                    ev.eventType,
                    ev.timestampRaw,
                    ev.timestampIso ?: "",
                    ev.timezoneStatus,
                    ev.source,
                    ev.notes
                ).joinToString(",") { csvEscape(it) }
            )
        }
        return sb.toString()
    }

    // ---------- 5. External AI Bundle Documents ----------

    fun buildCaseSummaryMarkdown(reportParts: List<ForensicCaseReport>): String {
        val primary = reportParts.first()
        val stats = primary.recoveryStats
        return buildString {
            appendLine("# DeepVault Case Summary (`${primary.caseId}`)")
            appendLine()
            appendLine("- **Report ID:** `${primary.reportId.substringBefore("-P")}` (Version ${primary.reportVersion}, Schema v${primary.schemaVersion})")
            appendLine("- **Generated At (UTC):** `${primary.generatedAtIso}`")
            appendLine("- **Total Parts in Bundle:** ${reportParts.size}")
            appendLine("- **Total Evidence Items:** ${primary.totalEvidenceInCase}")
            appendLine("- **Device:** `${primary.deviceInfo.manufacturer} ${primary.deviceInfo.model}` (Android ${primary.deviceInfo.androidRelease}, SDK ${primary.deviceInfo.sdkInt})")
            appendLine("- **Acquisition Method:** ${primary.acquisitionMethod}")
            appendLine("- **Sanitized Report:** `${primary.isSanitized}` ${if (primary.redactionSummary.isNotEmpty()) "(${primary.redactionSummary.joinToString(", ")})" else ""}")
            appendLine()
            appendLine("## Key Statistics")
            appendLine("- Complete Structurally Verified Files: **${stats.recoveredCompleteCount}**")
            appendLine("- Partial / Carved Streams: **${stats.partialOrCarvedCount}**")
            appendLine("- Structural Warnings / Corrupted Files: **${stats.corruptedOrWarningCount}**")
            appendLine("- Extension Mismatches: **${stats.extensionMismatchCount}**")
            appendLine("- Exact SHA-256 Duplicate Groups: **${stats.duplicateGroupCount}**")
            appendLine("- Total Bytes Analyzed: **${stats.totalBytesAnalyzed}**")
            appendLine()
            appendLine("## Bundle File Inventory")
            appendLine("- `forensic_report.json` — Complete machine-readable Schema v1.0 forensic dataset")
            appendLine("- `forensic_report.md` — Detailed human- and LLM-readable forensic report")
            appendLine("- `evidence_inventory.csv` — File inventory with magic signatures, structure checks, and SHA-256/MD5/SHA-1 hashes")
            appendLine("- `metadata_summary.csv` — Normalized key-value metadata table with provenance sources")
            appendLine("- `timeline.csv` — Chronological event sequence with explicit timezone statuses")
            appendLine("- `ai_analysis_brief.md` — Ready-to-paste external AI analysis instructions and prompts")
            appendLine("- `sha256_manifest.txt` — Cryptographic SHA-256 manifest for verifying report and evidence integrity")
        }
    }

    fun buildExternalAiBriefMarkdown(report: ForensicCaseReport): String {
        return buildString {
            appendLine("# External AI Forensic Analysis Brief (`${report.caseId}`)")
            appendLine()
            appendLine("> **Deterministic Offline Notice:** This bundle was generated locally by **DeepVault v${report.appVersion}** without any internal AI/LLM processing. All facts in `forensic_report.json` and `forensic_report.md` are categorized as `observed`, `embedded`, `filesystem`, `application_recorded`, or `rule_based_finding`.")
            appendLine()
            appendLine("## Guidelines for External AI Review")
            appendLine("When analyzing the attached DeepVault files:")
            appendLine("1. Cite every file using its stable **Evidence ID** (e.g., `DV-000001`) and **SHA-256 hash**.")
            appendLine("2. Distinguish between **embedded metadata** (EXIF, PDF Info, OOXML, ID3, ISOBMFF), **filesystem metadata** (`lastModified`), and **rule-based findings**.")
            appendLine("3. Treat `unavailable_fields` as missing metadata — do **not** assume tampering solely because metadata was stripped.")
            appendLine("4. Respect `timezone_status` (`explicit_utc`, `explicit_offset`, vs `local_unverified`).")
            appendLine()
            appendLine("## Copy-Ready Analysis Prompts")
            appendLine()
            PromptTemplateType.entries.forEach { tmpl ->
                appendLine("### ${tmpl.title}")
                appendLine("```text")
                appendLine(buildPromptText(tmpl, report, includeExcerpt = true))
                appendLine("```")
                appendLine()
            }
        }
    }

    fun buildPromptText(
        template: PromptTemplateType,
        report: ForensicCaseReport,
        includeExcerpt: Boolean = true
    ): String {
        val coreInstruction = when (template) {
            PromptTemplateType.ANOMALY_REVIEW ->
                "Review the attached DeepVault forensic report (Case ${report.caseId}, Report ${report.reportId}). Identify all evidence items with extension mismatches, missing EOF/EOI/IEND/EOCD markers, partial carving status, or metadata inconsistencies. For each anomaly, cite the Evidence ID (DV-XXXXXX), SHA-256 hash, observed facts, and explain non-malicious vs. suspicious possibilities without over-claiming."
            PromptTemplateType.TIMELINE_RECONSTRUCTION ->
                "Reconstruct a chronological timeline for Case ${report.caseId} using the `timeline` array and per-file timestamps in the attached DeepVault report. Separate events with `explicit_utc` or `explicit_offset` from `local_unverified` timestamps. Highlight any cases where embedded creation dates (EXIF/PDF/OOXML) post-date filesystem modification dates."
            PromptTemplateType.METADATA_CONSISTENCY ->
                "Perform a cross-field metadata consistency audit on Case ${report.caseId}. Compare binary magic signatures, detected formats, embedded EXIF/PDF/OOXML/audio tags, and filesystem attributes across all ${report.totalEvidenceInCase} evidence items. List which fields were unavailable and note any parser warnings."
            PromptTemplateType.EXECUTIVE_SUMMARY ->
                "Write a clear, objective Forensic Executive Summary for Case ${report.caseId} (Report ${report.reportId}). Summarize the acquisition scope, total files evaluated (${report.recoveryStats.totalFilesEvaluated}), structural integrity breakdown, duplicate clusters (${report.recoveryStats.duplicateGroupCount}), key rule-based findings, and technical limitations."
            PromptTemplateType.CORRUPTION_TRIAGE ->
                "Triage the structural integrity and recovery completeness of all files in Case ${report.caseId}. Group evidence IDs into: (1) Complete & Verified, (2) Partial / Carved Candidates requiring manual inspection, and (3) Corrupted / Truncated streams. Cite specific `structure_detail` and `corruption_indicators` for each item."
        }

        if (!includeExcerpt) return coreInstruction

        val excerptItems = report.evidenceItems.take(5).joinToString("\n") { item ->
            "- ${item.evidenceId} | ${item.currentFilename} | Format: ${item.detectedFormat} | Size: ${item.sizeBytes} B | Structure: ${item.structureCheck} | ExtMismatch: ${item.extensionMismatch} | SHA-256: ${item.sha256}"
        }
        return buildString {
            appendLine(coreInstruction)
            appendLine()
            appendLine("--- Case Context Excerpt ---")
            appendLine("Case ID: ${report.caseId} | Report ID: ${report.reportId} v${report.reportVersion} | Sanitized: ${report.isSanitized}")
            appendLine("Files Evaluated: ${report.recoveryStats.totalFilesEvaluated} | Complete: ${report.recoveryStats.recoveredCompleteCount} | Warnings/Corrupted: ${report.recoveryStats.corruptedOrWarningCount}")
            if (excerptItems.isNotBlank()) {
                appendLine("Evidence Sample:")
                appendLine(excerptItems)
            }
        }.trim()
    }

    // ---------- 6. SHA-256 Manifest Generation & Integrity Verification ----------

    private fun buildSha256ManifestText(
        primary: ForensicCaseReport,
        exportedFiles: List<ExportedReportFile>,
        evidenceHashes: List<HashManifestEntry>
    ): String {
        val sb = StringBuilder()
        sb.appendLine("# DeepVault Cryptographic SHA-256 Manifest")
        sb.appendLine("# Report ID: ${primary.reportId.substringBefore("-P")} (Version ${primary.reportVersion}, Schema v${primary.schemaVersion})")
        sb.appendLine("# Case ID: ${primary.caseId}")
        sb.appendLine("# Generated At (UTC): ${primary.generatedAtIso}")
        sb.appendLine("# Sanitized: ${primary.isSanitized}")
        sb.appendLine("# Disclaimer: A report hash proves the byte-level integrity of the exported report files being compared; it does not independently prove the accuracy of the underlying forensic conclusions.")
        sb.appendLine("#")
        sb.appendLine("# [SECTION 1: EXPORTED REPORT FILES]")
        exportedFiles.forEach { ef ->
            sb.appendLine("${ef.sha256}  ${ef.file.name}  # role=${ef.role} size=${ef.sizeBytes}")
        }
        sb.appendLine("#")
        sb.appendLine("# [SECTION 2: EVIDENCE ITEM HASHES]")
        evidenceHashes.distinctBy { it.evidenceId }.forEach { eh ->
            sb.appendLine("# EVIDENCE ${eh.evidenceId}  sha256=${eh.sha256}  md5=${eh.md5 ?: "n/a"}  sha1=${eh.sha1 ?: "n/a"}  size=${eh.sizeBytes}  target=${eh.hashTarget}  name=${eh.filename}")
        }
        return sb.toString()
    }

    /**
     * Verifies the byte-level integrity of an [ExportedReportBundle] by reading its
     * `sha256_manifest.txt` and recomputing the SHA-256 hash of every exported report file on disk.
     */
    fun verifyExportedBundle(bundle: ExportedReportBundle): ReportVerificationResult {
        return verifyManifestFile(bundle.manifestFile, expectedReportId = bundle.reportId)
    }

    /**
     * Parses a `sha256_manifest.txt` file and verifies every listed report file in the same directory.
     */
    fun verifyManifestFile(manifestFile: File, expectedReportId: String = "UNKNOWN"): ReportVerificationResult {
        val nowIso = ForensicTimeUtil.nowIsoUtc()
        if (!manifestFile.exists() || !manifestFile.isFile) {
            return ReportVerificationResult(
                reportId = expectedReportId,
                verifiedAtIso = nowIso,
                allPassed = false,
                fileResults = emptyList(),
                summaryMessage = "Manifest file missing: ${manifestFile.path}"
            )
        }

        val parentDir = manifestFile.parentFile ?: File(".")
        val lines = manifestFile.readLines(StandardCharsets.UTF_8)
        var parsedReportId = expectedReportId
        val checkResults = mutableListOf<FileHashCheckResult>()

        for (rawLine in lines) {
            val trimmed = rawLine.trim()
            if (trimmed.startsWith("# Report ID:")) {
                parsedReportId = trimmed.removePrefix("# Report ID:").trim().substringBefore(" ")
                continue
            }
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue

            // Format: <64-hex-sha256>  <filename>  # role=<role> size=<size>
            val beforeComment = trimmed.substringBefore("#").trim()
            val commentPart = trimmed.substringAfter("#", "").trim()
            val parts = beforeComment.split(Regex("""\s+"""), limit = 2)
            if (parts.size < 2) continue
            val expectedSha = parts[0].lowercase(Locale.US)
            val fileName = parts[1].trim()
            val role = Regex("""role=([^\s]+)""").find(commentPart)?.groupValues?.getOrNull(1) ?: "report_file"

            val target = File(parentDir, fileName)
            val exists = target.exists() && target.isFile
            val actualSha = if (exists) ForensicAnalyzer.computeSha256Sync(target).lowercase(Locale.US) else null
            val passed = exists && actualSha == expectedSha

            checkResults.add(
                FileHashCheckResult(
                    filename = fileName,
                    role = role,
                    expectedSha256 = expectedSha,
                    actualSha256 = actualSha,
                    fileExists = exists,
                    passed = passed
                )
            )
        }

        val allOk = checkResults.isNotEmpty() && checkResults.all { it.passed }
        val passedCount = checkResults.count { it.passed }
        val summary = if (allOk) {
            "Verified $passedCount of ${checkResults.size} exported report files against SHA-256 manifest: ALL PASSED."
        } else {
            val failedNames = checkResults.filterNot { it.passed }.joinToString(", ") { it.filename }
            "Verification FAILED (${passedCount}/${checkResults.size} passed). Mismatched or missing: $failedNames"
        }

        return ReportVerificationResult(
            reportId = parsedReportId,
            verifiedAtIso = nowIso,
            allPassed = allOk,
            fileResults = checkResults,
            summaryMessage = summary
        )
    }

    // ---------- 7. User-Initiated Clipboard & Share Intent Helpers ----------

    fun copyTextToClipboard(context: Context, label: String, text: String) {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        cm.setPrimaryClip(ClipData.newPlainText(label, text))
    }

    fun shareExportedFile(context: Context, exportedFile: ExportedReportFile) {
        runCatching {
            val uri: Uri = FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                exportedFile.file
            )
            val mime = when (exportedFile.format.uppercase(Locale.US)) {
                "JSON" -> "application/json"
                "MARKDOWN" -> "text/markdown"
                "PDF" -> "application/pdf"
                "CSV" -> "text/csv"
                else -> "text/plain"
            }
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = mime
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, "DeepVault Forensic Report (${exportedFile.file.name})")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(Intent.createChooser(intent, "Export Forensic Report").apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            })
        }
    }

    fun shareReportFile(context: Context, file: File, mimeType: String = "application/json") {
        runCatching {
            if (!file.exists()) return
            val uri: Uri = FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                file
            )
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = mimeType
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, "DeepVault Export (${file.name})")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(Intent.createChooser(intent, "Share DeepVault Archive").apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            })
        }
    }

    fun shareExportedBundle(context: Context, bundle: ExportedReportBundle) {
        runCatching {
            val uris = ArrayList<Uri>()
            bundle.files.forEach { ef ->
                if (ef.file.exists()) {
                    uris.add(
                        FileProvider.getUriForFile(
                            context,
                            "${context.packageName}.fileprovider",
                            ef.file
                        )
                    )
                }
            }
            if (uris.isEmpty()) return
            val intent = Intent(Intent.ACTION_SEND_MULTIPLE).apply {
                type = "*/*"
                putParcelableArrayListExtra(Intent.EXTRA_STREAM, uris)
                putExtra(
                    Intent.EXTRA_SUBJECT,
                    "DeepVault External AI Forensic Bundle (${bundle.caseId} - ${bundle.reportId})"
                )
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(Intent.createChooser(intent, "Share External AI Forensic Bundle").apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            })
        }
    }

    private fun csvEscape(value: String): String {
        val needsQuotes = value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r')
        return if (needsQuotes) {
            "\"${value.replace("\"", "\"\"")}\""
        } else {
            value
        }
    }

    private fun escapeMd(value: String): String =
        value.replace("|", "\\|").replace("\n", " ").replace("\r", "")
}
