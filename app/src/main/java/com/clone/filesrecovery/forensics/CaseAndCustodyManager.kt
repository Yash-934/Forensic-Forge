package com.clone.filesrecovery.forensics

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale

/**
 * Section 7: Investigation Case Manager models.
 * Clearly distinguishes:
 *  - Original file timestamps (filesystem lastModified)
 *  - Metadata timestamps (EXIF / PDF / OOXML / container creation)
 *  - Scan timestamps (when DeepVault scanned/discovered the artifact)
 *  - Recovery timestamps (when DeepVault carved/copied a recovered artifact)
 *  - Application-generated timestamps (when added/annotated in the case)
 */
data class CaseEvidenceItem(
    val evidenceId: String,
    val caseId: String,
    val originalSourcePathOrUri: String?,
    val currentFileName: String,
    val sourceAccessibilityStatus: String, // "accessible_read_only", "saf_authorized_uri", "carved_output", "inaccessible_or_removed"
    val fileSize: Long,
    val detectedFormat: String,
    val detectedMimeType: String,
    val sha256: String,
    val md5: String?,
    val sha1: String?,
    val recoveryMethod: String,
    val recoveryClassification: RecoveryClassification,
    val validationSummary: String,
    val relevantMetadataSummary: Map<String, String>,
    val originalFileTimestampIso: String?,
    val metadataTimestampIso: String?,
    val scanTimestampIso: String?,
    val recoveryTimestampIso: String?,
    val appAddedTimestampIso: String,
    val bookmarked: Boolean = false,
    val tags: List<String> = emptyList(),
    val analystNotes: String = ""
)

data class InvestigationCase(
    val caseId: String,
    val title: String,
    val investigatorName: String,
    val description: String,
    val createdAtIso: String,
    val updatedAtIso: String,
    val readOnlyMode: Boolean = true,
    val operatingModeAtCreation: String = "Standard",
    val evidenceItems: List<CaseEvidenceItem> = emptyList(),
    val caseNotes: String = ""
)

/**
 * Side-by-side comparison result for two evidence items (Section 7 & Section 12).
 */
data class EvidenceComparisonResult(
    val leftEvidence: CaseEvidenceItem,
    val rightEvidence: CaseEvidenceItem,
    val exactByteMatch: Boolean,
    val sizeDifferenceBytes: Long,
    val formatMatch: Boolean,
    val recoveryMethodComparison: String,
    val classificationComparison: String,
    val timestampDifferences: List<String>,
    val sharedMetadataKeys: List<String>,
    val differingMetadataEntries: List<Triple<String, String, String>> // key, leftVal, rightVal
)

/**
 * Section 8: Chronological, append-oriented, hash-linked Chain of Custody log entry.
 */
enum class CustodyActionType(val code: String, val label: String) {
    CASE_CREATED("CASE_CREATED", "Case Created"),
    EVIDENCE_ADDED("EVIDENCE_ADDED", "Evidence Added to Case"),
    HASH_CALCULATED("HASH_CALCULATED", "Cryptographic Hash Calculated"),
    FILE_VERIFIED("FILE_VERIFIED", "File / Manifest Integrity Verified"),
    RECOVERY_ATTEMPT("RECOVERY_ATTEMPT", "Recovery / Carving Attempted"),
    FILE_REPAIR_ATTEMPT("FILE_REPAIR_ATTEMPT", "Non-Destructive File Repair Executed"),
    REPORT_EXPORTED("REPORT_EXPORTED", "Forensic Report / External AI Bundle Exported"),
    ANALYST_ANNOTATION("ANALYST_ANNOTATION", "Analyst Note / Bookmark / Tag Updated"),
    EVIDENCE_REMOVED("EVIDENCE_REMOVED", "Evidence Removed from Case"),
    PERMISSION_OR_MODE_CHANGE("PERMISSION_OR_MODE_CHANGE", "Privilege / Storage Access Mode Evaluated")
}

data class ChainOfCustodyEntry(
    val sequenceNumber: Int,
    val timestampUtc: String,
    val actionType: CustodyActionType,
    val caseId: String,
    val evidenceId: String?,
    val actorOrComponent: String,
    val details: String,
    val previousEntryHash: String,
    val entrySha256: String
)

data class ChainIntegrityVerification(
    val verifiedAtUtc: String,
    val totalEntriesChecked: Int,
    val isChainIntact: Boolean,
    val brokenAtSequence: Int?,
    val summaryMessage: String,
    val transparencyNotice: String = "A local SHA-256 hash-linked audit log detects accidental edits or naive file modifications on disk, but is not tamper-proof against an adversary with root/device control who recomputes the entire chain."
)

/**
 * Section 9: Scan Checkpoint & Scan History models for resumable, bounded scans.
 */
data class ScanCheckpoint(
    val checkpointId: String,
    val categoryName: String,
    val operatingMode: String,
    val startedAtIso: String,
    val updatedAtIso: String,
    val status: String, // "IN_PROGRESS", "INTERRUPTED_RESUMABLE", "COMPLETED", "CANCELLED", "FAILED"
    val scannedDirectoriesCount: Int,
    val discoveredFilesCount: Int,
    val bytesEvaluated: Long,
    val lastProcessedPath: String,
    val completedRootPaths: List<String>,
    val DiscoveredPathsSnapshot: List<String>,
    val errorSummary: String? = null
)

data class ScanHistoryEntry(
    val sessionId: String,
    val categoryName: String,
    val operatingMode: String,
    val startedAtIso: String,
    val finishedAtIso: String,
    val status: String,
    val filesDiscovered: Int,
    val bytesEvaluated: Long,
    val durationMs: Long,
    val notes: String
)

/**
 * Persistent manager for Investigation Cases, Hash-Linked Chain of Custody,
 * and Resumable Scan Checkpoints / History.
 */
object CaseAndCustodyManager {

    private const val CASES_FILE = "investigation_cases_v1.json"
    private const val CUSTODY_LOG_FILE = "chain_of_custody_v1.json"
    private const val CHECKPOINTS_FILE = "scan_checkpoints_v1.json"
    private const val SCAN_HISTORY_FILE = "scan_history_v1.json"
    private const val GENESIS_PREV_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    private fun storeFile(context: Context, name: String): File = File(context.filesDir, name)

    // =========================================================================
    // 1. CHAIN OF CUSTODY (HASH-LINKED APPEND-ONLY LOG)
    // =========================================================================

    @Synchronized
    fun loadCustodyLog(context: Context): List<ChainOfCustodyEntry> {
        val f = storeFile(context, CUSTODY_LOG_FILE)
        if (!f.exists()) return emptyList()
        return runCatching {
            val arr = JSONArray(f.readText(StandardCharsets.UTF_8))
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                ChainOfCustodyEntry(
                    sequenceNumber = o.getInt("seq"),
                    timestampUtc = o.getString("timestampUtc"),
                    actionType = runCatching { CustodyActionType.valueOf(o.getString("actionType")) }
                        .getOrDefault(CustodyActionType.ANALYST_ANNOTATION),
                    caseId = o.optString("caseId", "CASE-DEFAULT"),
                    evidenceId = o.optString("evidenceId", "").takeIf { it.isNotBlank() },
                    actorOrComponent = o.optString("actor", "DeepVault Local Analyst"),
                    details = o.optString("details", ""),
                    previousEntryHash = o.getString("previousEntryHash"),
                    entrySha256 = o.getString("entrySha256")
                )
            }
        }.getOrDefault(emptyList())
    }

    @Synchronized
    fun appendCustodyEvent(
        context: Context,
        actionType: CustodyActionType,
        caseId: String,
        evidenceId: String? = null,
        actorOrComponent: String = "DeepVault Engine",
        details: String
    ): ChainOfCustodyEntry {
        val existing = loadCustodyLog(context)
        val nextSeq = (existing.maxOfOrNull { it.sequenceNumber } ?: 0) + 1
        val prevHash = existing.lastOrNull()?.entrySha256 ?: GENESIS_PREV_HASH
        val nowIso = ForensicTimeUtil.nowIsoUtc()
        val entryHash = computeCustodyEntryHash(
            seq = nextSeq,
            timestampUtc = nowIso,
            actionCode = actionType.code,
            caseId = caseId,
            evidenceId = evidenceId ?: "",
            actor = actorOrComponent,
            details = details,
            prevHash = prevHash
        )
        val entry = ChainOfCustodyEntry(
            sequenceNumber = nextSeq,
            timestampUtc = nowIso,
            actionType = actionType,
            caseId = caseId,
            evidenceId = evidenceId,
            actorOrComponent = actorOrComponent,
            details = details,
            previousEntryHash = prevHash,
            entrySha256 = entryHash
        )
        val updated = existing + entry
        saveCustodyLogInternal(context, updated)
        return entry
    }

    private fun saveCustodyLogInternal(context: Context, entries: List<ChainOfCustodyEntry>) {
        val arr = JSONArray()
        entries.forEach { e ->
            arr.put(
                JSONObject().apply {
                    put("seq", e.sequenceNumber)
                    put("timestampUtc", e.timestampUtc)
                    put("actionType", e.actionType.name)
                    put("caseId", e.caseId)
                    put("evidenceId", e.evidenceId ?: "")
                    put("actor", e.actorOrComponent)
                    put("details", e.details)
                    put("previousEntryHash", e.previousEntryHash)
                    put("entrySha256", e.entrySha256)
                }
            )
        }
        storeFile(context, CUSTODY_LOG_FILE).writeText(arr.toString(2), StandardCharsets.UTF_8)
    }

    fun computeCustodyEntryHash(
        seq: Int,
        timestampUtc: String,
        actionCode: String,
        caseId: String,
        evidenceId: String,
        actor: String,
        details: String,
        prevHash: String
    ): String {
        val canonical = "$seq|$timestampUtc|$actionCode|$caseId|$evidenceId|$actor|$details|$prevHash"
        val digest = MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(canonical.toByteArray(StandardCharsets.UTF_8))
        return bytes.joinToString("") { String.format(Locale.US, "%02x", it.toInt() and 0xFF) }
    }

    @Synchronized
    fun verifyCustodyChainIntegrity(context: Context): ChainIntegrityVerification {
        val log = loadCustodyLog(context)
        val nowIso = ForensicTimeUtil.nowIsoUtc()
        if (log.isEmpty()) {
            return ChainIntegrityVerification(
                verifiedAtUtc = nowIso,
                totalEntriesChecked = 0,
                isChainIntact = true,
                brokenAtSequence = null,
                summaryMessage = "Chain of Custody log is empty (0 entries); ready to record genesis event."
            )
        }

        var expectedPrev = GENESIS_PREV_HASH
        for ((idx, entry) in log.withIndex()) {
            val expectedSeq = idx + 1
            if (entry.sequenceNumber != expectedSeq) {
                return ChainIntegrityVerification(
                    verifiedAtUtc = nowIso,
                    totalEntriesChecked = idx + 1,
                    isChainIntact = false,
                    brokenAtSequence = entry.sequenceNumber,
                    summaryMessage = "Sequence gap detected at index $idx (expected #$expectedSeq, found #${entry.sequenceNumber})."
                )
            }
            if (entry.previousEntryHash != expectedPrev) {
                return ChainIntegrityVerification(
                    verifiedAtUtc = nowIso,
                    totalEntriesChecked = idx + 1,
                    isChainIntact = false,
                    brokenAtSequence = entry.sequenceNumber,
                    summaryMessage = "Previous-hash link broken at entry #${entry.sequenceNumber}."
                )
            }
            val recomputed = computeCustodyEntryHash(
                seq = entry.sequenceNumber,
                timestampUtc = entry.timestampUtc,
                actionCode = entry.actionType.code,
                caseId = entry.caseId,
                evidenceId = entry.evidenceId ?: "",
                actor = entry.actorOrComponent,
                details = entry.details,
                prevHash = entry.previousEntryHash
            )
            if (!recomputed.equals(entry.entrySha256, ignoreCase = true)) {
                return ChainIntegrityVerification(
                    verifiedAtUtc = nowIso,
                    totalEntriesChecked = idx + 1,
                    isChainIntact = false,
                    brokenAtSequence = entry.sequenceNumber,
                    summaryMessage = "Content hash mismatch at entry #${entry.sequenceNumber} (expected ${entry.entrySha256.take(12)}…, computed ${recomputed.take(12)}…)."
                )
            }
            expectedPrev = entry.entrySha256
        }

        return ChainIntegrityVerification(
            verifiedAtUtc = nowIso,
            totalEntriesChecked = log.size,
            isChainIntact = true,
            brokenAtSequence = null,
            summaryMessage = "All ${log.size} hash-linked Chain of Custody entries verified intact from genesis to head (${expectedPrev.take(16)}…)."
        )
    }

    // =========================================================================
    // 2. INVESTIGATION CASE MANAGER
    // =========================================================================

    @Synchronized
    fun loadCases(context: Context): List<InvestigationCase> {
        val f = storeFile(context, CASES_FILE)
        if (!f.exists()) return emptyList()
        return runCatching {
            parseCasesJson(f.readText(StandardCharsets.UTF_8))
        }.getOrDefault(emptyList())
    }

    @Synchronized
    fun ensureDefaultCase(context: Context, defaultCaseId: String, operatingMode: String): InvestigationCase {
        val existing = loadCases(context)
        if (existing.isNotEmpty()) return existing.first()
        return createCase(
            context = context,
            caseId = defaultCaseId,
            title = "Default Device Investigation",
            investigatorName = "Local Forensic Analyst",
            description = "Primary offline digital forensics and recovery workspace.",
            operatingMode = operatingMode
        )
    }

    @Synchronized
    fun createCase(
        context: Context,
        caseId: String,
        title: String,
        investigatorName: String,
        description: String,
        operatingMode: String
    ): InvestigationCase {
        val now = ForensicTimeUtil.nowIsoUtc()
        val cleanId = caseId.trim().ifBlank { "CASE-${System.currentTimeMillis() % 100000}" }
        val newCase = InvestigationCase(
            caseId = cleanId,
            title = title.trim().ifBlank { "Investigation $cleanId" },
            investigatorName = investigatorName.trim().ifBlank { "Local Analyst" },
            description = description.trim(),
            createdAtIso = now,
            updatedAtIso = now,
            readOnlyMode = true,
            operatingModeAtCreation = operatingMode,
            evidenceItems = emptyList(),
            caseNotes = ""
        )
        val all = listOf(newCase) + loadCases(context).filterNot { it.caseId == cleanId }
        saveCasesInternal(context, all)
        appendCustodyEvent(
            context = context,
            actionType = CustodyActionType.CASE_CREATED,
            caseId = cleanId,
            details = "Created investigation case '${newCase.title}' (Investigator: ${newCase.investigatorName}, Mode: $operatingMode)"
        )
        return newCase
    }

    @Synchronized
    fun addOrUpdateEvidenceInCase(
        context: Context,
        caseId: String,
        record: ForensicEvidenceRecord,
        scanTimestampIso: String? = null
    ): InvestigationCase? {
        val cases = loadCases(context).toMutableList()
        val idx = cases.indexOfFirst { it.caseId == caseId }
        if (idx < 0) return null
        val target = cases[idx]
        val existingItem = target.evidenceItems.firstOrNull { it.evidenceId == record.evidenceId }

        val fsTime = record.extractedFields.firstOrNull { it.key == "filesystem.last_modified_utc" }?.value
        val metaTime = record.timeline.firstOrNull { it.eventType != "filesystem_last_modified" && it.eventType != "application_recovery_event" }?.let {
            it.timestampIso ?: it.timestampRaw
        }

        val classification = when {
            record.recoveryStatus == "unreadable" -> RecoveryClassification.FAILED
            record.structureCheck == "corrupted" -> RecoveryClassification.CORRUPTED
            record.structureCheck == "passed" -> RecoveryClassification.RECOVERED
            record.completenessStatus == "partial" || record.structureCheck == "warning" -> RecoveryClassification.PARTIALLY_RECOVERED
            else -> RecoveryClassification.UNVERIFIED
        }

        val metaMap = linkedMapOf<String, String>()
        record.extractedFields.take(15).forEach { mf ->
            metaMap[mf.key] = mf.value
        }

        val newItem = CaseEvidenceItem(
            evidenceId = record.evidenceId,
            caseId = caseId,
            originalSourcePathOrUri = record.sourceLocation,
            currentFileName = record.currentFilename,
            sourceAccessibilityStatus = if (record.recoveryStatus == "unreadable") "inaccessible_or_removed" else "accessible_read_only",
            fileSize = record.sizeBytes,
            detectedFormat = record.detectedFormat,
            detectedMimeType = record.detectedMimeType,
            sha256 = record.sha256,
            md5 = record.md5,
            sha1 = record.sha1,
            recoveryMethod = record.recoveryMethod,
            recoveryClassification = classification,
            validationSummary = "${record.structureCheck.uppercase(Locale.US)}: ${record.structureDetail}",
            relevantMetadataSummary = metaMap,
            originalFileTimestampIso = fsTime,
            metadataTimestampIso = metaTime,
            scanTimestampIso = scanTimestampIso ?: ForensicTimeUtil.nowIsoUtc(),
            recoveryTimestampIso = record.recoveryTimestampIso,
            appAddedTimestampIso = existingItem?.appAddedTimestampIso ?: ForensicTimeUtil.nowIsoUtc(),
            bookmarked = existingItem?.bookmarked ?: false,
            tags = existingItem?.tags ?: emptyList(),
            analystNotes = existingItem?.analystNotes ?: ""
        )

        val updatedItems = target.evidenceItems.filterNot { it.evidenceId == record.evidenceId } + newItem
        val updatedCase = target.copy(
            updatedAtIso = ForensicTimeUtil.nowIsoUtc(),
            evidenceItems = updatedItems
        )
        cases[idx] = updatedCase
        saveCasesInternal(context, cases)

        if (existingItem == null) {
            appendCustodyEvent(
                context = context,
                actionType = CustodyActionType.EVIDENCE_ADDED,
                caseId = caseId,
                evidenceId = record.evidenceId,
                details = "Added evidence '${record.currentFilename}' (${record.detectedFormat}, ${record.sizeBytes} bytes, SHA-256=${record.sha256.take(16)}…, Classification=${classification.code})"
            )
        }
        return updatedCase
    }

    @Synchronized
    fun updateEvidenceAnnotation(
        context: Context,
        caseId: String,
        evidenceId: String,
        bookmarked: Boolean? = null,
        tags: List<String>? = null,
        analystNotes: String? = null
    ): InvestigationCase? {
        val cases = loadCases(context).toMutableList()
        val idx = cases.indexOfFirst { it.caseId == caseId }
        if (idx < 0) return null
        val target = cases[idx]
        val itemIdx = target.evidenceItems.indexOfFirst { it.evidenceId == evidenceId }
        if (itemIdx < 0) return null

        val oldItem = target.evidenceItems[itemIdx]
        val newItem = oldItem.copy(
            bookmarked = bookmarked ?: oldItem.bookmarked,
            tags = tags ?: oldItem.tags,
            analystNotes = analystNotes ?: oldItem.analystNotes
        )
        val nextList = target.evidenceItems.toMutableList().apply { set(itemIdx, newItem) }
        val updatedCase = target.copy(
            updatedAtIso = ForensicTimeUtil.nowIsoUtc(),
            evidenceItems = nextList
        )
        cases[idx] = updatedCase
        saveCasesInternal(context, cases)

        appendCustodyEvent(
            context = context,
            actionType = CustodyActionType.ANALYST_ANNOTATION,
            caseId = caseId,
            evidenceId = evidenceId,
            details = "Updated analyst annotation on $evidenceId (bookmarked=${newItem.bookmarked}, tags=${newItem.tags.joinToString(",")}, notesLen=${newItem.analystNotes.length})"
        )
        return updatedCase
    }

    @Synchronized
    fun removeEvidenceFromCase(
        context: Context,
        caseId: String,
        evidenceId: String,
        reason: String = "Removed by analyst from case scope"
    ): InvestigationCase? {
        val cases = loadCases(context).toMutableList()
        val idx = cases.indexOfFirst { it.caseId == caseId }
        if (idx < 0) return null
        val target = cases[idx]
        val removed = target.evidenceItems.firstOrNull { it.evidenceId == evidenceId } ?: return target
        val updatedCase = target.copy(
            updatedAtIso = ForensicTimeUtil.nowIsoUtc(),
            evidenceItems = target.evidenceItems.filterNot { it.evidenceId == evidenceId }
        )
        cases[idx] = updatedCase
        saveCasesInternal(context, cases)

        appendCustodyEvent(
            context = context,
            actionType = CustodyActionType.EVIDENCE_REMOVED,
            caseId = caseId,
            evidenceId = evidenceId,
            details = "Removed evidence '${removed.currentFileName}' ($evidenceId) from case $caseId. Reason: $reason"
        )
        return updatedCase
    }

    /**
     * Compares two evidence items side-by-side (hashes, size, format, recovery method, timestamps, metadata).
     */
    fun compareEvidenceItems(left: CaseEvidenceItem, right: CaseEvidenceItem): EvidenceComparisonResult {
        val exactMatch = left.sha256.length == 64 && left.sha256.equals(right.sha256, ignoreCase = true)
        val sizeDiff = left.fileSize - right.fileSize
        val formatMatch = left.detectedFormat == right.detectedFormat
        val recComp = if (left.recoveryMethod == right.recoveryMethod) {
            "Both acquired via '${left.recoveryMethod}'"
        } else {
            "Left: '${left.recoveryMethod}' vs Right: '${right.recoveryMethod}'"
        }
        val classComp = if (left.recoveryClassification == right.recoveryClassification) {
            "Both classified as ${left.recoveryClassification.code}"
        } else {
            "Left: ${left.recoveryClassification.code} vs Right: ${right.recoveryClassification.code}"
        }

        val tsDiffs = mutableListOf<String>()
        if (left.originalFileTimestampIso != right.originalFileTimestampIso) {
            tsDiffs.add("Filesystem Last-Modified: Left=${left.originalFileTimestampIso ?: "unavailable"} | Right=${right.originalFileTimestampIso ?: "unavailable"}")
        }
        if (left.metadataTimestampIso != right.metadataTimestampIso) {
            tsDiffs.add("Embedded Metadata Time: Left=${left.metadataTimestampIso ?: "unavailable"} | Right=${right.metadataTimestampIso ?: "unavailable"}")
        }
        if (left.recoveryTimestampIso != right.recoveryTimestampIso) {
            tsDiffs.add("Recovery Timestamp: Left=${left.recoveryTimestampIso ?: "n/a"} | Right=${right.recoveryTimestampIso ?: "n/a"}")
        }

        val allKeys = (left.relevantMetadataSummary.keys + right.relevantMetadataSummary.keys).distinct()
        val shared = mutableListOf<String>()
        val differing = mutableListOf<Triple<String, String, String>>()
        for (k in allKeys) {
            val lv = left.relevantMetadataSummary[k] ?: "<absent>"
            val rv = right.relevantMetadataSummary[k] ?: "<absent>"
            if (lv == rv) {
                shared.add("$k = $lv")
            } else {
                differing.add(Triple(k, lv, rv))
            }
        }

        return EvidenceComparisonResult(
            leftEvidence = left,
            rightEvidence = right,
            exactByteMatch = exactMatch,
            sizeDifferenceBytes = sizeDiff,
            formatMatch = formatMatch,
            recoveryMethodComparison = recComp,
            classificationComparison = classComp,
            timestampDifferences = tsDiffs,
            sharedMetadataKeys = shared,
            differingMetadataEntries = differing
        )
    }

    /**
     * Exports a portable JSON backup of all investigation cases and chain of custody entries,
     * and allows restoring from backup.
     */
    @Synchronized
    fun exportCasesBackupFile(context: Context, targetDir: File): File {
        targetDir.mkdirs()
        val backupFile = File(targetDir, "deepvault_cases_backup_${System.currentTimeMillis()}.json")
        val root = JSONObject().apply {
            put("schema", "deepvault_case_backup_v1")
            put("exportedAtUtc", ForensicTimeUtil.nowIsoUtc())
            put("cases", serializeCasesArray(loadCases(context)))
        }
        backupFile.writeText(root.toString(2), StandardCharsets.UTF_8)
        return backupFile
    }

    @Synchronized
    fun restoreCasesFromBackupJson(context: Context, jsonText: String): Int {
        val root = JSONObject(jsonText)
        val arr = root.getJSONArray("cases")
        val restored = parseCasesJson(arr.toString())
        if (restored.isNotEmpty()) {
            val merged = (restored + loadCases(context)).distinctBy { it.caseId }
            saveCasesInternal(context, merged)
        }
        return restored.size
    }

    private fun saveCasesInternal(context: Context, cases: List<InvestigationCase>) {
        val arr = serializeCasesArray(cases)
        storeFile(context, CASES_FILE).writeText(arr.toString(2), StandardCharsets.UTF_8)
    }

    private fun serializeCasesArray(cases: List<InvestigationCase>): JSONArray {
        val arr = JSONArray()
        cases.forEach { c ->
            val evArr = JSONArray()
            c.evidenceItems.forEach { item ->
                val metaObj = JSONObject()
                item.relevantMetadataSummary.forEach { (k, v) -> metaObj.put(k, v) }
                evArr.put(
                    JSONObject().apply {
                        put("evidenceId", item.evidenceId)
                        put("caseId", item.caseId)
                        put("originalSourcePathOrUri", item.originalSourcePathOrUri ?: "")
                        put("currentFileName", item.currentFileName)
                        put("sourceAccessibilityStatus", item.sourceAccessibilityStatus)
                        put("fileSize", item.fileSize)
                        put("detectedFormat", item.detectedFormat)
                        put("detectedMimeType", item.detectedMimeType)
                        put("sha256", item.sha256)
                        put("md5", item.md5 ?: "")
                        put("sha1", item.sha1 ?: "")
                        put("recoveryMethod", item.recoveryMethod)
                        put("recoveryClassification", item.recoveryClassification.name)
                        put("validationSummary", item.validationSummary)
                        put("relevantMetadataSummary", metaObj)
                        put("originalFileTimestampIso", item.originalFileTimestampIso ?: "")
                        put("metadataTimestampIso", item.metadataTimestampIso ?: "")
                        put("scanTimestampIso", item.scanTimestampIso ?: "")
                        put("recoveryTimestampIso", item.recoveryTimestampIso ?: "")
                        put("appAddedTimestampIso", item.appAddedTimestampIso)
                        put("bookmarked", item.bookmarked)
                        put("tags", JSONArray(item.tags))
                        put("analystNotes", item.analystNotes)
                    }
                )
            }
            arr.put(
                JSONObject().apply {
                    put("caseId", c.caseId)
                    put("title", c.title)
                    put("investigatorName", c.investigatorName)
                    put("description", c.description)
                    put("createdAtIso", c.createdAtIso)
                    put("updatedAtIso", c.updatedAtIso)
                    put("readOnlyMode", c.readOnlyMode)
                    put("operatingModeAtCreation", c.operatingModeAtCreation)
                    put("caseNotes", c.caseNotes)
                    put("evidenceItems", evArr)
                }
            )
        }
        return arr
    }

    private fun parseCasesJson(jsonText: String): List<InvestigationCase> {
        val arr = JSONArray(jsonText)
        return (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            val evArr = o.optJSONArray("evidenceItems") ?: JSONArray()
            val items = (0 until evArr.length()).map { j ->
                val eo = evArr.getJSONObject(j)
                val metaObj = eo.optJSONObject("relevantMetadataSummary") ?: JSONObject()
                val metaMap = linkedMapOf<String, String>()
                val keys = metaObj.keys()
                while (keys.hasNext()) {
                    val k = keys.next()
                    metaMap[k] = metaObj.optString(k, "")
                }
                val tagsArr = eo.optJSONArray("tags") ?: JSONArray()
                val tagsList = (0 until tagsArr.length()).mapNotNull { tagsArr.optString(it).takeIf { s -> s.isNotBlank() } }

                CaseEvidenceItem(
                    evidenceId = eo.getString("evidenceId"),
                    caseId = eo.optString("caseId", o.getString("caseId")),
                    originalSourcePathOrUri = eo.optString("originalSourcePathOrUri", "").takeIf { it.isNotBlank() },
                    currentFileName = eo.optString("currentFileName", "unknown"),
                    sourceAccessibilityStatus = eo.optString("sourceAccessibilityStatus", "accessible_read_only"),
                    fileSize = eo.optLong("fileSize", 0L),
                    detectedFormat = eo.optString("detectedFormat", "UNKNOWN"),
                    detectedMimeType = eo.optString("detectedMimeType", "application/octet-stream"),
                    sha256 = eo.optString("sha256", ""),
                    md5 = eo.optString("md5", "").takeIf { it.isNotBlank() },
                    sha1 = eo.optString("sha1", "").takeIf { it.isNotBlank() },
                    recoveryMethod = eo.optString("recoveryMethod", "direct_inspection"),
                    recoveryClassification = runCatching {
                        RecoveryClassification.valueOf(eo.optString("recoveryClassification", "UNVERIFIED"))
                    }.getOrDefault(RecoveryClassification.UNVERIFIED),
                    validationSummary = eo.optString("validationSummary", ""),
                    relevantMetadataSummary = metaMap,
                    originalFileTimestampIso = eo.optString("originalFileTimestampIso", "").takeIf { it.isNotBlank() },
                    metadataTimestampIso = eo.optString("metadataTimestampIso", "").takeIf { it.isNotBlank() },
                    scanTimestampIso = eo.optString("scanTimestampIso", "").takeIf { it.isNotBlank() },
                    recoveryTimestampIso = eo.optString("recoveryTimestampIso", "").takeIf { it.isNotBlank() },
                    appAddedTimestampIso = eo.optString("appAddedTimestampIso", ForensicTimeUtil.nowIsoUtc()),
                    bookmarked = eo.optBoolean("bookmarked", false),
                    tags = tagsList,
                    analystNotes = eo.optString("analystNotes", "")
                )
            }
            InvestigationCase(
                caseId = o.getString("caseId"),
                title = o.optString("title", o.getString("caseId")),
                investigatorName = o.optString("investigatorName", "Local Analyst"),
                description = o.optString("description", ""),
                createdAtIso = o.optString("createdAtIso", ForensicTimeUtil.nowIsoUtc()),
                updatedAtIso = o.optString("updatedAtIso", ForensicTimeUtil.nowIsoUtc()),
                readOnlyMode = o.optBoolean("readOnlyMode", true),
                operatingModeAtCreation = o.optString("operatingModeAtCreation", "Standard"),
                evidenceItems = items,
                caseNotes = o.optString("caseNotes", "")
            )
        }
    }

    // =========================================================================
    // 3. SCAN CHECKPOINTING & SCAN HISTORY (Section 9)
    // =========================================================================

    @Synchronized
    fun saveScanCheckpoint(context: Context, checkpoint: ScanCheckpoint) {
        val o = JSONObject().apply {
            put("checkpointId", checkpoint.checkpointId)
            put("categoryName", checkpoint.categoryName)
            put("operatingMode", checkpoint.operatingMode)
            put("startedAtIso", checkpoint.startedAtIso)
            put("updatedAtIso", checkpoint.updatedAtIso)
            put("status", checkpoint.status)
            put("scannedDirectoriesCount", checkpoint.scannedDirectoriesCount)
            put("discoveredFilesCount", checkpoint.discoveredFilesCount)
            put("bytesEvaluated", checkpoint.bytesEvaluated)
            put("lastProcessedPath", checkpoint.lastProcessedPath)
            put("completedRootPaths", JSONArray(checkpoint.completedRootPaths))
            put("discoveredPathsSnapshot", JSONArray(checkpoint.DiscoveredPathsSnapshot.take(500)))
            put("errorSummary", checkpoint.errorSummary ?: "")
        }
        storeFile(context, CHECKPOINTS_FILE).writeText(o.toString(2), StandardCharsets.UTF_8)
    }

    @Synchronized
    fun loadLastScanCheckpoint(context: Context): ScanCheckpoint? {
        val f = storeFile(context, CHECKPOINTS_FILE)
        if (!f.exists()) return null
        return runCatching {
            val o = JSONObject(f.readText(StandardCharsets.UTF_8))
            val rootsArr = o.optJSONArray("completedRootPaths") ?: JSONArray()
            val snapArr = o.optJSONArray("discoveredPathsSnapshot") ?: JSONArray()
            ScanCheckpoint(
                checkpointId = o.getString("checkpointId"),
                categoryName = o.getString("categoryName"),
                operatingMode = o.optString("operatingMode", "Standard"),
                startedAtIso = o.getString("startedAtIso"),
                updatedAtIso = o.getString("updatedAtIso"),
                status = o.getString("status"),
                scannedDirectoriesCount = o.optInt("scannedDirectoriesCount", 0),
                discoveredFilesCount = o.optInt("discoveredFilesCount", 0),
                bytesEvaluated = o.optLong("bytesEvaluated", 0L),
                lastProcessedPath = o.optString("lastProcessedPath", ""),
                completedRootPaths = (0 until rootsArr.length()).mapNotNull { rootsArr.optString(it) },
                DiscoveredPathsSnapshot = (0 until snapArr.length()).mapNotNull { snapArr.optString(it) },
                errorSummary = o.optString("errorSummary", "").takeIf { it.isNotBlank() }
            )
        }.getOrNull()
    }

    @Synchronized
    fun clearScanCheckpoint(context: Context) {
        val f = storeFile(context, CHECKPOINTS_FILE)
        if (f.exists()) f.delete()
    }

    @Synchronized
    fun appendScanHistory(context: Context, entry: ScanHistoryEntry) {
        val existing = loadScanHistory(context)
        val updated = (listOf(entry) + existing).take(50)
        val arr = JSONArray()
        updated.forEach { h ->
            arr.put(
                JSONObject().apply {
                    put("sessionId", h.sessionId)
                    put("categoryName", h.categoryName)
                    put("operatingMode", h.operatingMode)
                    put("startedAtIso", h.startedAtIso)
                    put("finishedAtIso", h.finishedAtIso)
                    put("status", h.status)
                    put("filesDiscovered", h.filesDiscovered)
                    put("bytesEvaluated", h.bytesEvaluated)
                    put("durationMs", h.durationMs)
                    put("notes", h.notes)
                }
            )
        }
        storeFile(context, SCAN_HISTORY_FILE).writeText(arr.toString(2), StandardCharsets.UTF_8)
    }

    @Synchronized
    fun loadScanHistory(context: Context): List<ScanHistoryEntry> {
        val f = storeFile(context, SCAN_HISTORY_FILE)
        if (!f.exists()) return emptyList()
        return runCatching {
            val arr = JSONArray(f.readText(StandardCharsets.UTF_8))
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                ScanHistoryEntry(
                    sessionId = o.getString("sessionId"),
                    categoryName = o.getString("categoryName"),
                    operatingMode = o.optString("operatingMode", "Standard"),
                    startedAtIso = o.getString("startedAtIso"),
                    finishedAtIso = o.getString("finishedAtIso"),
                    status = o.getString("status"),
                    filesDiscovered = o.optInt("filesDiscovered", 0),
                    bytesEvaluated = o.optLong("bytesEvaluated", 0L),
                    durationMs = o.optLong("durationMs", 0L),
                    notes = o.optString("notes", "")
                )
            }
        }.getOrDefault(emptyList())
    }
}
