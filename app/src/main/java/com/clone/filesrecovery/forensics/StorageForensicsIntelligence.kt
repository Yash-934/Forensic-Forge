package com.clone.filesrecovery.forensics

import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.StatFs
import android.provider.DocumentsContract
import com.clone.filesrecovery.data.FileCategory
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.util.Locale
import java.util.UUID
import kotlin.math.ln
import kotlin.math.min

/**
 * Classification of hidden files and directories discovered within accessible storage.
 * Designed to be neutral and evidence-based without assuming every hidden file is malicious or suspicious.
 */
enum class HiddenArtifactCategory(val label: String, val defaultExplanation: String) {
    MEDIA_INDEXING_CONTROL_NOMEDIA(
        "Media Indexing Control (.nomedia)",
        "Standard Android marker file that instructs MediaStore to exclude this directory and its subdirectories from gallery/media indexing."
    ),
    TRASH_OR_RECYCLE_ARTIFACT(
        "Trash / Recycle Bin Artifact",
        "File or folder located inside an Android MediaStore trash prefix (.trashed-*) or OEM gallery recycle bin."
    ),
    SYSTEM_OR_APP_CACHE_HIDDEN(
        "Hidden Thumbnail / App Cache",
        "Dot-prefixed cache or thumbnail container (.thumbnails, .thumbdata*) used by gallery or media apps to speed up previews."
    ),
    DOT_PREFIXED_FILE_OR_DIR(
        "Dot-Prefixed File or Directory",
        "Standard Unix/Android convention (leading '.') used by applications or users to hide configuration, state, or working files from default file listings."
    ),
    UNUSUAL_NAMING_OR_STRUCTURE(
        "Unusual Filename, Extension, or Nesting",
        "File exhibits compound/double extensions, non-standard control characters, or deep directory nesting that warrants manual review."
    )
}

/**
 * Technical verification level for encryption findings.
 * Strictly separates format-verified encryption headers from statistical high-entropy indicators.
 */
enum class EncryptionVerificationStatus(val label: String) {
    CONFIRMED_FORMAT_HEADER("Confirmed Encrypted Format Header"),
    POTENTIAL_HIGH_ENTROPY_INDICATOR("Potential Encryption / High-Entropy Indicator"),
    COMPRESSED_MEDIA_NOT_ENCRYPTED("Standard Compressed Media / Archive (Not Encrypted)")
}

data class RecognizedCategoryStat(
    val categoryId: String,
    val title: String,
    val fileCount: Int,
    val totalBytes: Long,
    val shareOfScannedBytesPercent: Double,
    val sampleExtensions: List<String>
)

data class HiddenArtifactFinding(
    val path: String,
    val name: String,
    val isDirectory: Boolean,
    val sizeBytes: Long,
    val lastModifiedMs: Long,
    val lastModifiedIso: String?,
    val category: HiddenArtifactCategory,
    val isNoMediaMarker: Boolean,
    val affectedDirectoryPath: String?,
    val mediaIndexingEffect: String?,
    val unusualIndicators: List<String>,
    val forensicNote: String
)

data class UnclassifiedFileFinding(
    val path: String,
    val name: String,
    val declaredExtension: String,
    val sizeBytes: Long,
    val lastModifiedIso: String?,
    val magicHeaderHex: String,
    val asciiPreview: String,
    val shannonEntropyBitsPerByte: Double,
    val printableAsciiRatio: Double,
    val classificationReason: String
)

data class EncryptionFinding(
    val path: String,
    val name: String,
    val declaredExtension: String,
    val sizeBytes: Long,
    val lastModifiedIso: String?,
    val verificationStatus: EncryptionVerificationStatus,
    val detectedMechanism: String,
    val technicalEvidence: String,
    val shannonEntropyBitsPerByte: Double,
    val magicHeaderHex: String,
    val limitationOrCaveat: String
)

data class SignatureMismatchFinding(
    val path: String,
    val name: String,
    val declaredExtension: String,
    val detectedFormat: String,
    val detectedMimeType: String,
    val magicHeaderHex: String,
    val sizeBytes: Long,
    val lastModifiedIso: String?,
    val explanation: String
)

data class InaccessibleStorageArea(
    val path: String,
    val areaType: String,
    val restrictionReason: String,
    val securityMechanism: String,
    val canBeAccessedViaSafOrPermission: Boolean,
    val forensicImpact: String
)

data class StorageForensicsExportResult(
    val jsonFile: File,
    val markdownFile: File,
    val jsonSha256: String,
    val markdownSha256: String,
    val exportedAtIso: String
)

/**
 * Comprehensive, deterministic report produced by the Storage Forensics Intelligence module.
 *
 * CRITICAL GUARANTEE:
 * - Never calculates encrypted data as (total storage - visible files).
 * - Clearly separates whole-device capacity statistics from DeepVault's accessible & scanned scope.
 */
data class StorageForensicsReport(
    val reportId: String,
    val generatedAtIso: String,
    val scanDurationMs: Long,
    val operatingMode: String,
    val storagePermissionStatus: String,
    val hasAllFilesAccess: Boolean,

    // Whole-device storage statistics (from StatFs on primary storage volume)
    val totalDeviceBytes: Long,
    val usedDeviceBytes: Long,
    val availableDeviceBytes: Long,
    val uninspectedSystemAndSandboxedBytes: Long,

    // Subset of storage accessible to and actually scanned by DeepVault
    val accessibleStorageBytes: Long,
    val bytesActuallyScanned: Long,
    val filesActuallyScanned: Int,
    val directoriesTraversed: Int,
    val inaccessibleDirectoriesCount: Int,
    val scannedRootPaths: List<String>,

    // Scan coverage & explicit calculation method
    val accessibleCoveragePercent: Double,
    val wholeDeviceInspectedPercent: Double,
    val coverageCalculationMethod: String,
    val scopeDistinctionExplanation: String,

    // Breakdown of recognized categories
    val recognizedCategories: List<RecognizedCategoryStat>,
    val totalRecognizedFiles: Int,
    val totalRecognizedBytes: Long,

    // Unknown or unclassified accessible files
    val unclassifiedFindings: List<UnclassifiedFileFinding>,
    val totalUnclassifiedFiles: Int,
    val totalUnclassifiedBytes: Long,

    // Hidden files & directories analysis
    val hiddenFindings: List<HiddenArtifactFinding>,
    val nomediaFilesCount: Int,
    val dotFilesCount: Int,
    val dotDirectoriesCount: Int,
    val trashedOrRecycleCount: Int,
    val unusualNamingOrStructureCount: Int,
    val totalHiddenBytes: Long,

    // Confirmed encryption vs potential high-entropy indicators
    val confirmedEncryptionFindings: List<EncryptionFinding>,
    val totalConfirmedEncryptedFiles: Int,
    val totalConfirmedEncryptedBytes: Long,
    val potentialEncryptionFindings: List<EncryptionFinding>,
    val totalPotentialEncryptedFiles: Int,
    val totalPotentialEncryptedBytes: Long,
    val compressedMediaHighEntropyCount: Int,
    val encryptionMethodologyNote: String,

    // File-extension / signature mismatches
    val signatureMismatches: List<SignatureMismatchFinding>,
    val totalSignatureMismatches: Int,

    // Unsupported or inaccessible areas
    val inaccessibleAreas: List<InaccessibleStorageArea>,
    val forensicLimitations: List<String>
) {
    fun toJsonString(): String {
        val root = JSONObject()
        root.put("schema", "deepvault.storage_forensics_intelligence.v1")
        root.put("report_id", reportId)
        root.put("generated_at_utc", generatedAtIso)
        root.put("scan_duration_ms", scanDurationMs)
        root.put("operating_mode", operatingMode)
        root.put("storage_permission_status", storagePermissionStatus)
        root.put("has_all_files_access", hasAllFilesAccess)

        val wholeDevice = JSONObject().apply {
            put("total_device_bytes", totalDeviceBytes)
            put("used_device_bytes", usedDeviceBytes)
            put("available_device_bytes", availableDeviceBytes)
            put("uninspected_system_and_sandboxed_bytes", uninspectedSystemAndSandboxedBytes)
        }
        root.put("whole_device_storage", wholeDevice)

        val accessibleScope = JSONObject().apply {
            put("accessible_storage_bytes", accessibleStorageBytes)
            put("bytes_actually_scanned", bytesActuallyScanned)
            put("files_actually_scanned", filesActuallyScanned)
            put("directories_traversed", directoriesTraversed)
            put("inaccessible_directories_encountered", inaccessibleDirectoriesCount)
            put("scanned_root_paths", JSONArray(scannedRootPaths))
            put("accessible_coverage_percent", round2(accessibleCoveragePercent))
            put("whole_device_inspected_percent", round2(wholeDeviceInspectedPercent))
            put("coverage_calculation_method", coverageCalculationMethod)
            put("scope_distinction_explanation", scopeDistinctionExplanation)
        }
        root.put("deepvault_scanned_scope", accessibleScope)

        val catArray = JSONArray()
        recognizedCategories.forEach { cat ->
            catArray.put(
                JSONObject().apply {
                    put("category_id", cat.categoryId)
                    put("title", cat.title)
                    put("file_count", cat.fileCount)
                    put("total_bytes", cat.totalBytes)
                    put("share_of_scanned_bytes_percent", round2(cat.shareOfScannedBytesPercent))
                    put("sample_extensions", JSONArray(cat.sampleExtensions))
                }
            )
        }
        root.put("recognized_categories", catArray)

        val hiddenObj = JSONObject().apply {
            put("total_hidden_findings", hiddenFindings.size)
            put("nomedia_files_count", nomediaFilesCount)
            put("dot_files_count", dotFilesCount)
            put("dot_directories_count", dotDirectoriesCount)
            put("trashed_or_recycle_count", trashedOrRecycleCount)
            put("unusual_naming_or_structure_count", unusualNamingOrStructureCount)
            put("total_hidden_bytes", totalHiddenBytes)
            val arr = JSONArray()
            hiddenFindings.take(250).forEach { h ->
                arr.put(
                    JSONObject().apply {
                        put("path", h.path)
                        put("name", h.name)
                        put("is_directory", h.isDirectory)
                        put("size_bytes", h.sizeBytes)
                        put("last_modified_utc", h.lastModifiedIso ?: JSONObject.NULL)
                        put("category", h.category.name)
                        put("category_label", h.category.label)
                        put("is_nomedia_marker", h.isNoMediaMarker)
                        put("affected_directory", h.affectedDirectoryPath ?: JSONObject.NULL)
                        put("media_indexing_effect", h.mediaIndexingEffect ?: JSONObject.NULL)
                        put("unusual_indicators", JSONArray(h.unusualIndicators))
                        put("forensic_note", h.forensicNote)
                    }
                )
            }
            put("findings", arr)
        }
        root.put("hidden_file_analysis", hiddenObj)

        val encObj = JSONObject().apply {
            put("methodology_note", encryptionMethodologyNote)
            put("confirmed_encrypted_files_count", totalConfirmedEncryptedFiles)
            put("confirmed_encrypted_bytes", totalConfirmedEncryptedBytes)
            put("potential_high_entropy_files_count", totalPotentialEncryptedFiles)
            put("potential_high_entropy_bytes", totalPotentialEncryptedBytes)
            put("compressed_media_high_entropy_excluded_count", compressedMediaHighEntropyCount)

            val confirmedArr = JSONArray()
            confirmedEncryptionFindings.forEach { e ->
                confirmedArr.put(
                    JSONObject().apply {
                        put("path", e.path)
                        put("name", e.name)
                        put("declared_extension", e.declaredExtension)
                        put("size_bytes", e.sizeBytes)
                        put("verification_status", e.verificationStatus.name)
                        put("detected_mechanism", e.detectedMechanism)
                        put("technical_evidence", e.technicalEvidence)
                        put("shannon_entropy_bits_per_byte", round2(e.shannonEntropyBitsPerByte))
                        put("magic_header_hex", e.magicHeaderHex)
                        put("caveat", e.limitationOrCaveat)
                    }
                )
            }
            put("confirmed_encryption_findings", confirmedArr)

            val potentialArr = JSONArray()
            potentialEncryptionFindings.forEach { e ->
                potentialArr.put(
                    JSONObject().apply {
                        put("path", e.path)
                        put("name", e.name)
                        put("declared_extension", e.declaredExtension)
                        put("size_bytes", e.sizeBytes)
                        put("verification_status", e.verificationStatus.name)
                        put("detected_mechanism", e.detectedMechanism)
                        put("technical_evidence", e.technicalEvidence)
                        put("shannon_entropy_bits_per_byte", round2(e.shannonEntropyBitsPerByte))
                        put("magic_header_hex", e.magicHeaderHex)
                        put("caveat", e.limitationOrCaveat)
                    }
                )
            }
            put("potential_encryption_indicators", potentialArr)
        }
        root.put("encryption_and_entropy_analysis", encObj)

        val mismatchArr = JSONArray()
        signatureMismatches.forEach { m ->
            mismatchArr.put(
                JSONObject().apply {
                    put("path", m.path)
                    put("name", m.name)
                    put("declared_extension", m.declaredExtension)
                    put("detected_format", m.detectedFormat)
                    put("detected_mime_type", m.detectedMimeType)
                    put("magic_header_hex", m.magicHeaderHex)
                    put("size_bytes", m.sizeBytes)
                    put("last_modified_utc", m.lastModifiedIso ?: JSONObject.NULL)
                    put("explanation", m.explanation)
                }
            )
        }
        root.put("signature_mismatches", mismatchArr)

        val unclassObj = JSONObject().apply {
            put("total_unclassified_files", totalUnclassifiedFiles)
            put("total_unclassified_bytes", totalUnclassifiedBytes)
            val arr = JSONArray()
            unclassifiedFindings.take(200).forEach { u ->
                arr.put(
                    JSONObject().apply {
                        put("path", u.path)
                        put("name", u.name)
                        put("declared_extension", u.declaredExtension)
                        put("size_bytes", u.sizeBytes)
                        put("magic_header_hex", u.magicHeaderHex)
                        put("ascii_preview", u.asciiPreview)
                        put("shannon_entropy_bits_per_byte", round2(u.shannonEntropyBitsPerByte))
                        put("printable_ascii_ratio", round2(u.printableAsciiRatio))
                        put("classification_reason", u.classificationReason)
                    }
                )
            }
            put("findings", arr)
        }
        root.put("unclassified_accessible_files", unclassObj)

        val inaccArr = JSONArray()
        inaccessibleAreas.forEach { a ->
            inaccArr.put(
                JSONObject().apply {
                    put("path", a.path)
                    put("area_type", a.areaType)
                    put("restriction_reason", a.restrictionReason)
                    put("security_mechanism", a.securityMechanism)
                    put("can_be_accessed_via_saf_or_permission", a.canBeAccessedViaSafOrPermission)
                    put("forensic_impact", a.forensicImpact)
                }
            )
        }
        root.put("unsupported_or_inaccessible_areas", inaccArr)
        root.put("forensic_limitations", JSONArray(forensicLimitations))

        return root.toString(2)
    }

    fun toMarkdownString(): String = buildString {
        appendLine("# DeepVault — Storage Forensics Intelligence Report")
        appendLine()
        appendLine("- **Report ID**: `$reportId`")
        appendLine("- **Generated At (UTC)**: `$generatedAtIso`")
        appendLine("- **Operating Mode**: `$operatingMode`")
        appendLine("- **Permission Status**: `$storagePermissionStatus`")
        appendLine("- **Scan Duration**: `${scanDurationMs} ms`")
        appendLine()
        appendLine("## 1. Whole-Device vs. Accessible Storage Scope")
        appendLine("| Metric | Value | Scope Basis |")
        appendLine("| :--- | :--- | :--- |")
        appendLine("| Total Device Capacity | `${formatBytesHuman(totalDeviceBytes)}` (`$totalDeviceBytes` B) | Whole-Device (`StatFs`) |")
        appendLine("| Used Device Storage | `${formatBytesHuman(usedDeviceBytes)}` (`$usedDeviceBytes` B) | Whole-Device (`StatFs`) |")
        appendLine("| Available Free Storage | `${formatBytesHuman(availableDeviceBytes)}` (`$availableDeviceBytes` B) | Whole-Device (`StatFs`) |")
        appendLine("| Storage Accessible to DeepVault | `${formatBytesHuman(accessibleStorageBytes)}` (`$accessibleStorageBytes` B) | Accessible User-Space Scope |")
        appendLine("| Bytes Actually Scanned | `${formatBytesHuman(bytesActuallyScanned)}` (`$bytesActuallyScanned` B) | Verified File Traversal |")
        appendLine("| Files Actually Scanned | `$filesActuallyScanned` files across `$directoriesTraversed` directories | Verified File Traversal |")
        appendLine("| Accessible Scan Coverage | `${String.format(Locale.US, "%.2f", accessibleCoveragePercent)}%` | `bytesActuallyScanned / accessibleStorageBytes` |")
        appendLine("| Whole-Device Inspected Share | `${String.format(Locale.US, "%.2f", wholeDeviceInspectedPercent)}%` | `bytesActuallyScanned / totalDeviceBytes` |")
        appendLine()
        appendLine("> **Coverage Calculation Method**: $coverageCalculationMethod")
        appendLine("> **Scope Distinction**: $scopeDistinctionExplanation")
        appendLine()
        appendLine("## 2. Recognized File Categories")
        appendLine("| Category | Files | Size | % of Scanned Bytes | Sample Extensions |")
        appendLine("| :--- | :--- | :--- | :--- | :--- |")
        recognizedCategories.forEach { cat ->
            appendLine("| ${cat.title} | ${cat.fileCount} | ${formatBytesHuman(cat.totalBytes)} | ${String.format(Locale.US, "%.2f", cat.shareOfScannedBytesPercent)}% | ${cat.sampleExtensions.joinToString(", ").ifBlank { "-" }} |")
        }
        appendLine()
        appendLine("## 3. Hidden File & `.nomedia` Intelligence")
        appendLine("- **Total Hidden / Special Findings**: `${hiddenFindings.size}` (`${formatBytesHuman(totalHiddenBytes)}`)")
        appendLine("- **`.nomedia` Markers Detected**: `$nomediaFilesCount`")
        appendLine("- **Dot-Prefixed Files**: `$dotFilesCount`")
        appendLine("- **Dot-Prefixed Directories**: `$dotDirectoriesCount`")
        appendLine("- **Trash / Recycle Artifacts**: `$trashedOrRecycleCount`")
        appendLine("- **Unusual Filenames / Nesting**: `$unusualNamingOrStructureCount`")
        appendLine()
        if (hiddenFindings.isNotEmpty()) {
            appendLine("| Path | Category | Size | Media Indexing / Forensic Note |")
            appendLine("| :--- | :--- | :--- | :--- |")
            hiddenFindings.take(40).forEach { h ->
                val note = h.mediaIndexingEffect ?: h.forensicNote
                appendLine("| `${h.path}` | ${h.category.label} | ${formatBytesHuman(h.sizeBytes)} | $note |")
            }
            appendLine()
        }
        appendLine("## 4. Encryption & High-Entropy Forensics")
        appendLine("- **Methodology**: $encryptionMethodologyNote")
        appendLine("- **Confirmed Encrypted Files (Format Header Verified)**: `$totalConfirmedEncryptedFiles` (`${formatBytesHuman(totalConfirmedEncryptedBytes)}`)")
        appendLine("- **Potential Encryption / High-Entropy Indicators**: `$totalPotentialEncryptedFiles` (`${formatBytesHuman(totalPotentialEncryptedBytes)}`)")
        appendLine("- **Standard Compressed Media (High Entropy, Not Encrypted)**: `$compressedMediaHighEntropyCount`")
        appendLine()
        if (confirmedEncryptionFindings.isNotEmpty()) {
            appendLine("### Confirmed Encryption Findings")
            confirmedEncryptionFindings.forEach { e ->
                appendLine("- **`${e.name}`** (`${e.path}`, `${formatBytesHuman(e.sizeBytes)}`): **${e.detectedMechanism}** — ${e.technicalEvidence} (Entropy: `${String.format(Locale.US, "%.2f", e.shannonEntropyBitsPerByte)}` bits/byte)")
            }
            appendLine()
        }
        if (potentialEncryptionFindings.isNotEmpty()) {
            appendLine("### Potential Encryption / High-Entropy Indicators")
            potentialEncryptionFindings.forEach { e ->
                appendLine("- **`${e.name}`** (`${e.path}`, `${formatBytesHuman(e.sizeBytes)}`): **${e.detectedMechanism}** — ${e.technicalEvidence} (*Caveat: ${e.limitationOrCaveat}*)")
            }
            appendLine()
        }
        appendLine("## 5. File-Extension / Binary Signature Mismatches ($totalSignatureMismatches)")
        if (signatureMismatches.isEmpty()) {
            appendLine("- No extension/signature mismatches detected in scanned scope.")
        } else {
            signatureMismatches.forEach { m ->
                appendLine("- **`${m.name}`** (`${m.path}`): Declared `.${m.declaredExtension}` vs Detected `${m.detectedFormat}` (`${m.detectedMimeType}`, magic `${m.magicHeaderHex}`) — ${m.explanation}")
            }
        }
        appendLine()
        appendLine("## 6. Unknown or Unclassified Accessible Files ($totalUnclassifiedFiles)")
        appendLine("- **Total Unclassified Size**: `${formatBytesHuman(totalUnclassifiedBytes)}`")
        unclassifiedFindings.take(25).forEach { u ->
            appendLine("- **`${u.name}`** (`${u.path}`, `${formatBytesHuman(u.sizeBytes)}`): Magic `${u.magicHeaderHex}`, Entropy `${String.format(Locale.US, "%.2f", u.shannonEntropyBitsPerByte)}` bits/byte — ${u.classificationReason}")
        }
        appendLine()
        appendLine("## 7. Unsupported or Inaccessible Storage Areas")
        inaccessibleAreas.forEach { a ->
            appendLine("- **`${a.path}`** (${a.areaType}): ${a.restrictionReason} [${a.securityMechanism}] — *${a.forensicImpact}*")
        }
        appendLine()
        appendLine("## 8. Forensic Limitations & Disclaimers")
        forensicLimitations.forEach { lim ->
            appendLine("- $lim")
        }
    }

    private fun round2(v: Double): Double = kotlin.math.round(v * 100.0) / 100.0
}

/**
 * Deterministic, on-device Storage Forensics Intelligence Engine.
 *
 * Performs genuine binary header verification, Shannon byte-entropy sampling, `.nomedia` impact
 * mapping, hidden file classification, and extension-signature mismatch detection without AI or mocks.
 */
object StorageForensicsAnalyzer {

    private const val ENTROPY_WINDOW_BYTES = 16 * 1024 // 16 KB per window (up to 3 windows = 48 KB max per file)
    private const val MAX_SCAN_DEPTH = 20

    private val CODE_AND_CONFIG_EXTS = setOf(
        "json", "xml", "html", "htm", "md", "txt", "csv", "tsv", "ini", "cfg", "conf", "properties", "yaml", "yml", "sh", "bat", "js", "py", "kt", "java", "c", "cpp", "sql"
    )
    private val DATABASE_EXTS = setOf(
        "db", "sqlite", "sqlite3", "db3", "wal", "journal", "shm", "realm", "leveldb"
    )
    private val PACKAGE_AND_BINARY_EXTS = setOf(
        "apk", "xapk", "apks", "aab", "dex", "odex", "vdex", "art", "so", "elf", "exe", "dll", "jar"
    )
    private val ARCHIVE_AND_DOC_EXTS = setOf(
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf", "epub", "mobi", "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "vcf", "ics"
    )
    private val KNOWN_ENCRYPTED_EXTS = setOf(
        "enc", "crypt", "crypt12", "crypt14", "crypt15", "gpg", "pgp", "asc", "age", "aes", "luks", "kdbx", "vault"
    )

    /**
     * Runs a complete, cancellation-safe Storage Forensics Intelligence scan over accessible roots
     * (or explicit roots provided for deterministic testing / SAF inspection).
     */
    suspend fun analyzeStorage(
        context: Context?,
        explicitRoots: List<File>? = null,
        environmentAssessment: DeviceEnvironmentAssessment? = null,
        totalDeviceCapacityOverride: Pair<Long, Long>? = null, // (totalBytes, availableBytes) for deterministic unit tests
        onProgress: ((filesScanned: Int, bytesScanned: Long, currentPath: String) -> Unit)? = null
    ): StorageForensicsReport = withContext(Dispatchers.IO) {
        val startMs = System.currentTimeMillis()
        val (hasAllFiles, permStatusLabel) = if (context != null) {
            DeviceEnvironmentAssessor.evaluateStoragePermissions(context)
        } else {
            true to "Direct Directory Inspection Mode"
        }
        val modeLabel = environmentAssessment?.recoveryModeLabel ?: "Standard"

        // 1. Whole-device capacity statistics via StatFs (never fabricated)
        val (totalDeviceBytes, availableDeviceBytes) = totalDeviceCapacityOverride ?: queryWholeDeviceCapacity(context, explicitRoots)
        val usedDeviceBytes = (totalDeviceBytes - availableDeviceBytes).coerceAtLeast(0L)

        // 2. Determine accessible roots to inspect
        val roots = LinkedHashSet<File>()
        if (!explicitRoots.isNullOrEmpty()) {
            explicitRoots.filter { it.exists() }.forEach { roots.add(it) }
        } else {
            Environment.getExternalStorageDirectory()?.takeIf { it.exists() && it.canRead() }?.let { roots.add(it) }
            if (context != null) {
                runCatching {
                    context.getExternalFilesDirs(null).filterNotNull().forEach { appExt ->
                        var cur: File? = appExt
                        while (cur != null && cur.name != "Android") {
                            cur = cur.parentFile
                        }
                        cur?.parentFile?.takeIf { it.exists() && it.canRead() }?.let { roots.add(it) }
                    }
                }
                // Always include app's own sandbox directories if external storage is restricted
                if (roots.isEmpty()) {
                    context.filesDir?.takeIf { it.exists() }?.let { roots.add(it) }
                    context.cacheDir?.takeIf { it.exists() }?.let { roots.add(it) }
                }
            }
        }

        val seenFilePaths = HashSet<String>()
        val seenDirPaths = HashSet<String>()
        var filesScanned = 0
        var bytesScanned = 0L
        var dirsTraversed = 0
        var inaccessibleDirsEncountered = 0

        // Category accumulators
        data class CatBucket(val id: String, val title: String, var count: Int = 0, var bytes: Long = 0L, val exts: MutableSet<String> = LinkedHashSet())
        val catPhotos = CatBucket("PHOTO", "Photos & Images")
        val catVideos = CatBucket("VIDEO", "Videos & Containers")
        val catAudio = CatBucket("AUDIO", "Audio & Voice Notes")
        val catDocs = CatBucket("DOCUMENT_ARCHIVE", "Documents & Archives")
        val catDatabases = CatBucket("DATABASE", "Databases & Logs (SQLite/WAL)")
        val catPackages = CatBucket("PACKAGE_BINARY", "App Packages & Executables (APK/DEX/SO)")
        val catCodeConfig = CatBucket("CODE_CONFIG_TEXT", "Structured Text, Config & Code")

        val hiddenFindings = ArrayList<HiddenArtifactFinding>()
        var nomediaCount = 0
        var dotFilesCount = 0
        var dotDirsCount = 0
        var trashedCount = 0
        var unusualCount = 0
        var totalHiddenBytes = 0L

        val unclassifiedFindings = ArrayList<UnclassifiedFileFinding>()
        var totalUnclassifiedFiles = 0
        var totalUnclassifiedBytes = 0L

        val confirmedEncrypted = ArrayList<EncryptionFinding>()
        var totalConfirmedEncFiles = 0
        var totalConfirmedEncBytes = 0L

        val potentialEncrypted = ArrayList<EncryptionFinding>()
        var totalPotentialEncFiles = 0
        var totalPotentialEncBytes = 0L
        var compressedMediaHighEntropyCount = 0

        val signatureMismatches = ArrayList<SignatureMismatchFinding>()
        val discoveredInaccessibleDirs = ArrayList<String>()

        val jobContext = currentCoroutineContext()
        for (root in roots) {
            val rootPath = root.absolutePath
            root.walkTopDown()
                .maxDepth(MAX_SCAN_DEPTH)
                .onEnter { dir ->
                    jobContext.ensureActive()
                    val abs = dir.absolutePath
                    // Skip DeepVault's own temporary staging caches to avoid self-feedback
                    if (abs.contains("/deep_carved_") || abs.contains("/saf_forensic_imports")) {
                        return@onEnter false
                    }
                    val readable = dir.canRead() && dir.list() != null
                    if (!readable) {
                        inaccessibleDirsEncountered++
                        if (discoveredInaccessibleDirs.size < 40) {
                            discoveredInaccessibleDirs.add(abs)
                        }
                        return@onEnter false
                    }
                    if (seenDirPaths.add(abs)) {
                        dirsTraversed++
                        inspectDirectoryForHiddenFindings(
                            dir = dir,
                            rootPath = rootPath,
                            hiddenFindings = hiddenFindings,
                            onDotDir = { dotDirsCount++ },
                            onTrashDir = { trashedCount++ },
                            onUnusualDir = { unusualCount++ }
                        )
                    }
                    true
                }
                .forEach { file ->
                    currentCoroutineContext().ensureActive()
                    if (!file.isFile) return@forEach
                    val abs = file.absolutePath
                    if (!seenFilePaths.add(abs)) return@forEach
                    if (!file.canRead()) {
                        inaccessibleDirsEncountered++
                        return@forEach
                    }

                    val size = file.length().coerceAtLeast(0L)
                    filesScanned++
                    bytesScanned += size

                    if (filesScanned % 20 == 0) {
                        onProgress?.invoke(filesScanned, bytesScanned, abs)
                    }

                    val lastModMs = file.lastModified()
                    val lastModIso = ForensicTimeUtil.epochMillisToIsoUtc(lastModMs)
                    val fileName = file.name
                    val rawExt = if (fileName.startsWith(".") && !fileName.substring(1).contains('.')) {
                        "" // Dotfile like ".nomedia" or ".bashrc" has no extension
                    } else {
                        fileName.substringAfterLast('.', "").lowercase(Locale.US)
                    }

                    // A. Hidden / .nomedia / unusual filename inspection
                    val hiddenItem = inspectFileForHiddenOrUnusual(file, rootPath, size, lastModMs, lastModIso)
                    if (hiddenItem != null) {
                        hiddenFindings.add(hiddenItem)
                        totalHiddenBytes += size
                        if (hiddenItem.isNoMediaMarker) nomediaCount++
                        if (fileName.startsWith(".")) dotFilesCount++
                        if (hiddenItem.category == HiddenArtifactCategory.TRASH_OR_RECYCLE_ARTIFACT) trashedCount++
                        if (hiddenItem.unusualIndicators.isNotEmpty()) unusualCount++
                    }

                    // Skip binary parsing on 0-byte marker files like empty .nomedia
                    if (size == 0L) {
                        if ( !fileName.equals(".nomedia", ignoreCase = true) ) {
                            totalUnclassifiedFiles++
                            if (unclassifiedFindings.size < 200) {
                                unclassifiedFindings.add(
                                    UnclassifiedFileFinding(
                                        path = abs,
                                        name = fileName,
                                        declaredExtension = rawExt,
                                        sizeBytes = 0L,
                                        lastModifiedIso = lastModIso,
                                        magicHeaderHex = "(empty 0-byte file)",
                                        asciiPreview = "",
                                        shannonEntropyBitsPerByte = 0.0,
                                        printableAsciiRatio = 0.0,
                                        classificationReason = "Zero-byte empty file; no header signature or payload present."
                                    )
                                )
                            }
                        }
                        return@forEach
                    }

                    // B. Read first 64 bytes for fast magic-byte & format header verification
                    val headerBuf = ByteArray(min(64, size.toInt()))
                    val headerRead = runCatching {
                        FileInputStream(file).use { it.read(headerBuf) }
                    }.getOrDefault(0).coerceAtLeast(0)
                    val headerSlice = if (headerRead == headerBuf.size) headerBuf else headerBuf.copyOf(headerRead)
                    val magicHex16 = headerSlice.take(16).joinToString(" ") { String.format(Locale.US, "%02X", it.toInt() and 0xFF) }

                    // C. Check for Confirmed Format-Level Encryption vs High-Entropy Indicators
                    val entropySample = computeBoundedEntropyAndAsciiRatio(file, size)
                    val encryptionCheck = inspectFileEncryption(
                        file = file,
                        fileName = fileName,
                        declaredExt = rawExt,
                        sizeBytes = size,
                        lastModifiedIso = lastModIso,
                        header = headerSlice,
                        magicHex16 = magicHex16,
                        entropy = entropySample.shannonEntropy,
                        printableAsciiRatio = entropySample.printableAsciiRatio
                    )
                    when (encryptionCheck?.verificationStatus) {
                        EncryptionVerificationStatus.CONFIRMED_FORMAT_HEADER -> {
                            totalConfirmedEncFiles++
                            totalConfirmedEncBytes += size
                            if (confirmedEncrypted.size < 200) confirmedEncrypted.add(encryptionCheck)
                        }
                        EncryptionVerificationStatus.POTENTIAL_HIGH_ENTROPY_INDICATOR -> {
                            totalPotentialEncFiles++
                            totalPotentialEncBytes += size
                            if (potentialEncrypted.size < 200) potentialEncrypted.add(encryptionCheck)
                        }
                        EncryptionVerificationStatus.COMPRESSED_MEDIA_NOT_ENCRYPTED -> {
                            compressedMediaHighEntropyCount++
                        }
                        null -> {}
                    }

                    // D. Magic-Byte Signature vs Extension Mismatch & Category Classification
                    val sigInfo = detectSignatureAndFormat(headerSlice, fileName, rawExt)
                    if (sigInfo.isMismatch && sigInfo.mismatchExplanation != null) {
                        signatureMismatches.add(
                            SignatureMismatchFinding(
                                path = abs,
                                name = fileName,
                                declaredExtension = rawExt.ifBlank { "(none)" },
                                detectedFormat = sigInfo.detectedFormat,
                                detectedMimeType = sigInfo.detectedMime,
                                magicHeaderHex = magicHex16,
                                sizeBytes = size,
                                lastModifiedIso = lastModIso,
                                explanation = sigInfo.mismatchExplanation
                            )
                        )
                    }

                    // E. Assign to Recognized Category or Unclassified Files
                    val assignedBucket: CatBucket? = when {
                        sigInfo.category == "PHOTO" || rawExt in FileCategory.PHOTO.extensions -> catPhotos
                        sigInfo.category == "VIDEO" || rawExt in FileCategory.VIDEO.extensions -> catVideos
                        sigInfo.category == "AUDIO" || rawExt in FileCategory.AUDIO.extensions -> catAudio
                        sigInfo.category == "DATABASE" || rawExt in DATABASE_EXTS -> catDatabases
                        sigInfo.category == "PACKAGE_BINARY" || rawExt in PACKAGE_AND_BINARY_EXTS -> catPackages
                        sigInfo.category == "DOCUMENT_ARCHIVE" || rawExt in ARCHIVE_AND_DOC_EXTS -> catDocs
                        sigInfo.category == "CODE_CONFIG_TEXT" || rawExt in CODE_AND_CONFIG_EXTS ||
                            (sigInfo.detectedFormat == "UNKNOWN" && entropySample.printableAsciiRatio >= 0.85 && size <= 10 * 1024 * 1024) -> catCodeConfig
                        else -> null
                    }

                    if (assignedBucket != null) {
                        assignedBucket.count++
                        assignedBucket.bytes += size
                        val extLabel = rawExt.ifBlank { sigInfo.detectedFormat.lowercase(Locale.US) }
                        if (extLabel.isNotBlank() && assignedBucket.exts.size < 8) {
                            assignedBucket.exts.add(extLabel)
                        }
                    } else {
                        totalUnclassifiedFiles++
                        totalUnclassifiedBytes += size
                        if (unclassifiedFindings.size < 200) {
                            val reason = when {
                                rawExt.isBlank() -> "No file extension and unrecognized binary header ($magicHex16)."
                                encryptionCheck?.verificationStatus == EncryptionVerificationStatus.POTENTIAL_HIGH_ENTROPY_INDICATOR ->
                                    "Unrecognized binary format with high byte entropy (${String.format(Locale.US, "%.2f", entropySample.shannonEntropy)} bits/byte)."
                                else -> "Extension '.$rawExt' is not a standard media/document category and magic bytes ($magicHex16) do not match known container signatures."
                            }
                            unclassifiedFindings.add(
                                UnclassifiedFileFinding(
                                    path = abs,
                                    name = fileName,
                                    declaredExtension = rawExt.ifBlank { "(none)" },
                                    sizeBytes = size,
                                    lastModifiedIso = lastModIso,
                                    magicHeaderHex = magicHex16,
                                    asciiPreview = buildAsciiPreview(headerSlice),
                                    shannonEntropyBitsPerByte = entropySample.shannonEntropy,
                                    printableAsciiRatio = entropySample.printableAsciiRatio,
                                    classificationReason = reason
                                )
                            )
                        }
                    }
                }
        }

        // 3. Compute accessible storage scope & coverage metrics transparently
        val accessibleStorageBytes = when {
            !explicitRoots.isNullOrEmpty() -> bytesScanned.coerceAtLeast(1L)
            hasAllFiles -> usedDeviceBytes.coerceAtLeast(bytesScanned)
            else -> bytesScanned
        }

        val accessibleCoveragePercent = if (accessibleStorageBytes > 0L) {
            ((bytesScanned.toDouble() / accessibleStorageBytes.toDouble()) * 100.0).coerceIn(0.0, 100.0)
        } else if (filesScanned == 0) {
            0.0
        } else {
            100.0
        }

        val wholeDeviceInspectedPercent = if (totalDeviceBytes > 0L) {
            ((bytesScanned.toDouble() / totalDeviceBytes.toDouble()) * 100.0).coerceIn(0.0, 100.0)
        } else {
            0.0
        }

        val uninspectedSystemAndSandboxedBytes = (usedDeviceBytes - bytesScanned).coerceAtLeast(0L)

        val allBuckets = listOf(catPhotos, catVideos, catAudio, catDocs, catDatabases, catPackages, catCodeConfig)
        val safeScannedDenominator = bytesScanned.coerceAtLeast(1L).toDouble()
        val recognizedStats = allBuckets.map { b ->
            RecognizedCategoryStat(
                categoryId = b.id,
                title = b.title,
                fileCount = b.count,
                totalBytes = b.bytes,
                shareOfScannedBytesPercent = if (bytesScanned > 0L) (b.bytes.toDouble() / safeScannedDenominator) * 100.0 else 0.0,
                sampleExtensions = b.exts.toList()
            )
        }
        val totalRecognizedFiles = recognizedStats.sumOf { it.fileCount }
        val totalRecognizedBytes = recognizedStats.sumOf { it.totalBytes }

        // 4. Build Unsupported / Inaccessible Areas list (combining Android architectural boundaries + encountered unreadable paths)
        val inaccessibleAreas = buildInaccessibleAreasList(
            hasAllFilesAccess = hasAllFiles,
            environmentAssessment = environmentAssessment,
            encounteredUnreadablePaths = discoveredInaccessibleDirs
        )

        val coverageFormula = "Accessible Coverage (%) = (Bytes Actually Scanned [$bytesScanned B] / Accessible Storage Scope [$accessibleStorageBytes B]) × 100 = ${String.format(Locale.US, "%.2f", accessibleCoveragePercent)}%. " +
            "Whole-Device Inspected Ratio (%) = (Bytes Actually Scanned [$bytesScanned B] / Total Device Capacity [$totalDeviceBytes B]) × 100 = ${String.format(Locale.US, "%.2f", wholeDeviceInspectedPercent)}%."

        val scopeDistinction = "Whole-device used storage (${formatBytesHuman(usedDeviceBytes)}) is reported by the kernel filesystem (StatFs) and includes the Android OS image, /data/data private app sandboxes, /data/app APK installations, and system caches. " +
            "DeepVault only inspects authorized user-space files (${formatBytesHuman(bytesScanned)} across $filesScanned files). " +
            "Uninspected system/sandboxed storage (${formatBytesHuman(uninspectedSystemAndSandboxedBytes)}) is restricted by Android sandboxing and is NEVER assumed or calculated to be encrypted user files."

        val encryptionMethodNote = "DeepVault never estimates encrypted data as (Total Storage − Visible Files). " +
            "Confirmed encryption is reported ONLY when verifiable format-level encryption headers/flags are parsed (e.g., ZIP general-purpose bit 0 / AES-256 0x9901, PDF /Encrypt dictionary, OpenSSL 'Salted__', LUKS header, PGP packets, OLE2 EncryptedPackage, or RAR encryption flags). " +
            "Potential encryption indicators are flagged using bounded Shannon byte-entropy (>= 7.80 bits/byte) on unidentified binary streams while explicitly excluding standard compressed media (JPEG, PNG, MP4, ZIP, APK)."

        val limitations = listOf(
            "Scoped Storage & App Sandboxing: Private application directories (/data/data/<package> and Android 11+ /sdcard/Android/data) cannot be traversed by standard user-space apps without explicit SAF directory grants or verified root access.",
            "File-Based Encryption (FBE) & TRIM: Modern Android devices encrypt filesystem blocks at rest using hardware-backed keys and issue TRIM/DISCARD on deletion; unallocated raw blocks are inaccessible.",
            "High-Entropy Ambiguity: Headerless encrypted streams (e.g., raw AES/ChaCha20 or SQLCipher pages) are statistically indistinguishable from raw deflate/LZMA compressed blobs without key material; therefore headerless high-entropy files are labeled strictly as 'Potential Encryption Indicators'.",
            "Hidden File Neutrality: Dot-prefixed directories, .nomedia markers, and thumbnail caches are standard Android mechanisms and do not inherently indicate malicious activity or intentional concealment."
        )

        val durationMs = (System.currentTimeMillis() - startMs).coerceAtLeast(1L)
        onProgress?.invoke(filesScanned, bytesScanned, "")

        StorageForensicsReport(
            reportId = "SFI-${UUID.randomUUID().toString().take(8).uppercase(Locale.US)}",
            generatedAtIso = ForensicTimeUtil.nowIsoUtc(),
            scanDurationMs = durationMs,
            operatingMode = modeLabel,
            storagePermissionStatus = permStatusLabel,
            hasAllFilesAccess = hasAllFiles,
            totalDeviceBytes = totalDeviceBytes,
            usedDeviceBytes = usedDeviceBytes,
            availableDeviceBytes = availableDeviceBytes,
            uninspectedSystemAndSandboxedBytes = uninspectedSystemAndSandboxedBytes,
            accessibleStorageBytes = accessibleStorageBytes,
            bytesActuallyScanned = bytesScanned,
            filesActuallyScanned = filesScanned,
            directoriesTraversed = dirsTraversed,
            inaccessibleDirectoriesCount = inaccessibleDirsEncountered,
            scannedRootPaths = roots.map { it.absolutePath },
            accessibleCoveragePercent = accessibleCoveragePercent,
            wholeDeviceInspectedPercent = wholeDeviceInspectedPercent,
            coverageCalculationMethod = coverageFormula,
            scopeDistinctionExplanation = scopeDistinction,
            recognizedCategories = recognizedStats,
            totalRecognizedFiles = totalRecognizedFiles,
            totalRecognizedBytes = totalRecognizedBytes,
            unclassifiedFindings = unclassifiedFindings,
            totalUnclassifiedFiles = totalUnclassifiedFiles,
            totalUnclassifiedBytes = totalUnclassifiedBytes,
            hiddenFindings = hiddenFindings,
            nomediaFilesCount = nomediaCount,
            dotFilesCount = dotFilesCount,
            dotDirectoriesCount = dotDirsCount,
            trashedOrRecycleCount = trashedCount,
            unusualNamingOrStructureCount = unusualCount,
            totalHiddenBytes = totalHiddenBytes,
            confirmedEncryptionFindings = confirmedEncrypted,
            totalConfirmedEncryptedFiles = totalConfirmedEncFiles,
            totalConfirmedEncryptedBytes = totalConfirmedEncBytes,
            potentialEncryptionFindings = potentialEncrypted,
            totalPotentialEncryptedFiles = totalPotentialEncFiles,
            totalPotentialEncryptedBytes = totalPotentialEncBytes,
            compressedMediaHighEntropyCount = compressedMediaHighEntropyCount,
            encryptionMethodologyNote = encryptionMethodNote,
            signatureMismatches = signatureMismatches,
            totalSignatureMismatches = signatureMismatches.size,
            inaccessibleAreas = inaccessibleAreas,
            forensicLimitations = limitations
        )
    }

    /**
     * Inspects a user-authorized SAF directory tree (`content://...`) and merges or builds
     * a local staging mirror so `analyzeStorage` can inspect files selected via Android SAF.
     */
    suspend fun copySafTreeForInspection(
        context: Context,
        treeUri: Uri,
        maxFiles: Int = 150
    ): File = withContext(Dispatchers.IO) {
        val stagingRoot = File(context.cacheDir, "saf_tree_inspection_${System.currentTimeMillis()}").apply { mkdirs() }
        val docId = runCatching { DocumentsContract.getTreeDocumentId(treeUri) }.getOrNull() ?: return@withContext stagingRoot
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, docId)
        val projection = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE
        )
        var copied = 0
        runCatching {
            context.contentResolver.query(childrenUri, projection, null, null, null)?.use { cursor ->
                while (cursor.moveToNext() && copied < maxFiles) {
                    currentCoroutineContext().ensureActive()
                    val childId = cursor.getString(0) ?: continue
                    val name = cursor.getString(1) ?: "item_$copied"
                    val mime = cursor.getString(2) ?: ""
                    if (mime == DocumentsContract.Document.MIME_TYPE_DIR) continue
                    val fileUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, childId)
                    val safeName = name.replace(Regex("""[\\/:*?"<>|]"""), "_")
                    val outFile = File(stagingRoot, safeName)
                    context.contentResolver.openInputStream(fileUri)?.use { input ->
                        outFile.outputStream().use { output ->
                            input.copyTo(output, 64 * 1024)
                        }
                    }
                    copied++
                }
            }
        }
        stagingRoot
    }

    /**
     * Exports the [StorageForensicsReport] to JSON and Markdown files on disk and computes their SHA-256 hashes.
     */
    fun exportReportFiles(report: StorageForensicsReport, outputRootDir: File): StorageForensicsExportResult {
        val dir = File(outputRootDir, "Storage_Intelligence_${report.reportId}").apply { mkdirs() }
        val jsonFile = File(dir, "${report.reportId}_storage_intelligence.json")
        val mdFile = File(dir, "${report.reportId}_storage_intelligence.md")

        jsonFile.writeText(report.toJsonString(), StandardCharsets.UTF_8)
        mdFile.writeText(report.toMarkdownString(), StandardCharsets.UTF_8)

        return StorageForensicsExportResult(
            jsonFile = jsonFile,
            markdownFile = mdFile,
            jsonSha256 = ForensicAnalyzer.computeSha256Sync(jsonFile),
            markdownSha256 = ForensicAnalyzer.computeSha256Sync(mdFile),
            exportedAtIso = ForensicTimeUtil.nowIsoUtc()
        )
    }

    private fun queryWholeDeviceCapacity(context: Context?, explicitRoots: List<File>?): Pair<Long, Long> {
        return runCatching {
            val candidates = buildList {
                explicitRoots?.firstOrNull()?.let { add(it) }
                runCatching { Environment.getExternalStorageDirectory() }.getOrNull()?.let { add(it) }
                runCatching { Environment.getDataDirectory() }.getOrNull()?.let { add(it) }
                context?.filesDir?.let { add(it) }
            }
            val valid = candidates.firstOrNull { it.exists() } ?: return@runCatching 0L to 0L
            val stat = StatFs(valid.path)
            val total = stat.blockCountLong * stat.blockSizeLong
            val avail = stat.availableBlocksLong * stat.blockSizeLong
            if (total > 0L) total to avail else 0L to 0L
        }.getOrDefault(0L to 0L)
    }

    private fun inspectDirectoryForHiddenFindings(
        dir: File,
        rootPath: String,
        hiddenFindings: MutableList<HiddenArtifactFinding>,
        onDotDir: () -> Unit,
        onTrashDir: () -> Unit,
        onUnusualDir: () -> Unit
    ) {
        val abs = dir.absolutePath
        if (abs == rootPath) return
        val name = dir.name
        val relPath = abs.removePrefix(rootPath).trimStart('/')
        val depth = relPath.count { it == '/' } + 1

        val isDotDir = name.startsWith(".")
        val isTrashDir = name.contains("trash", ignoreCase = true) ||
            name.contains("recycle", ignoreCase = true) ||
            abs.contains("/LOST.DIR", ignoreCase = true)
        val isThumbOrCache = name.equals(".thumbnails", ignoreCase = true) ||
            name.equals(".cache", ignoreCase = true)

        val unusualReasons = ArrayList<String>()
        if (depth >= 12) {
            unusualReasons.add("Deep directory nesting ($depth levels below scan root)")
        }
        if (name.isNotBlank() && name.trim().isEmpty()) {
            unusualReasons.add("Directory name consists solely of whitespace characters")
        }
        if (name.any { it.code < 32 }) {
            unusualReasons.add("Directory name contains ASCII control characters")
        }

        if (!isDotDir && !isTrashDir && unusualReasons.isEmpty()) return

        if (isDotDir) onDotDir()
        if (isTrashDir) onTrashDir()
        if (unusualReasons.isNotEmpty()) onUnusualDir()

        val category = when {
            isTrashDir -> HiddenArtifactCategory.TRASH_OR_RECYCLE_ARTIFACT
            isThumbOrCache -> HiddenArtifactCategory.SYSTEM_OR_APP_CACHE_HIDDEN
            unusualReasons.isNotEmpty() && !isDotDir -> HiddenArtifactCategory.UNUSUAL_NAMING_OR_STRUCTURE
            else -> HiddenArtifactCategory.DOT_PREFIXED_FILE_OR_DIR
        }

        val lastModMs = dir.lastModified()
        if (hiddenFindings.size < 400) {
            hiddenFindings.add(
                HiddenArtifactFinding(
                    path = abs,
                    name = name,
                    isDirectory = true,
                    sizeBytes = 0L,
                    lastModifiedMs = lastModMs,
                    lastModifiedIso = ForensicTimeUtil.epochMillisToIsoUtc(lastModMs),
                    category = category,
                    isNoMediaMarker = false,
                    affectedDirectoryPath = abs,
                    mediaIndexingEffect = if (isDotDir) {
                        "Dot-prefixed directory ('$name') is skipped by default Android MediaStore gallery scanners."
                    } else null,
                    unusualIndicators = unusualReasons,
                    forensicNote = category.defaultExplanation
                )
            )
        }
    }

    private fun inspectFileForHiddenOrUnusual(
        file: File,
        rootPath: String,
        sizeBytes: Long,
        lastModMs: Long,
        lastModIso: String?
    ): HiddenArtifactFinding? {
        val abs = file.absolutePath
        val name = file.name
        val parentPath = file.parent ?: rootPath
        val relPath = abs.removePrefix(rootPath).trimStart('/')
        val isNoMedia = name.equals(".nomedia", ignoreCase = true)
        val isDotFile = name.startsWith(".")
        val isJavaHidden = runCatching { file.isHidden }.getOrDefault(false)
        val inHiddenParent = relPath.split('/').dropLast(1).any { it.startsWith(".") }
        val isTrashFile = name.startsWith(".trashed-", ignoreCase = true) ||
            relPath.contains(".Trash", ignoreCase = true) ||
            relPath.contains(".recycle", ignoreCase = true) ||
            relPath.contains("trashBin", ignoreCase = true)
        val isThumbCache = name.startsWith(".thumbdata", ignoreCase = true) ||
            relPath.contains("/.thumbnails/", ignoreCase = true)

        val unusualIndicators = ArrayList<String>()
        // Check for double/compound extensions (e.g., document.pdf.exe, photo.jpg.apk, archive.zip.bin)
        val parts = name.trimStart('.').split('.')
        if (parts.size >= 3) {
            val secondLast = parts[parts.size - 2].lowercase(Locale.US)
            val last = parts.last().lowercase(Locale.US)
            val knownMediaOrDoc = FileCategory.fromExtension(secondLast) != null
            val suspiciousSecondStage = last in setOf("apk", "exe", "sh", "bin", "dat", "enc", "crypt", "dex", "so", "jar", "zip")
            if (knownMediaOrDoc && suspiciousSecondStage) {
                unusualIndicators.add("Compound extension (.$secondLast.$last) combines media/document type with binary/archive/encrypted suffix")
            }
        }
        if (name.any { it.code < 32 || it.code == 0x202E }) {
            unusualIndicators.add("Filename contains control or Unicode Right-to-Left Override (U+202E) characters")
        }
        val depth = relPath.count { it == '/' } + 1
        if (depth >= 12) {
            unusualIndicators.add("Located in deeply nested directory structure ($depth levels)")
        }

        if (!isNoMedia && !isDotFile && !isJavaHidden && !inHiddenParent && !isTrashFile && !isThumbCache && unusualIndicators.isEmpty()) {
            return null
        }

        val category = when {
            isNoMedia -> HiddenArtifactCategory.MEDIA_INDEXING_CONTROL_NOMEDIA
            isTrashFile -> HiddenArtifactCategory.TRASH_OR_RECYCLE_ARTIFACT
            isThumbCache -> HiddenArtifactCategory.SYSTEM_OR_APP_CACHE_HIDDEN
            unusualIndicators.isNotEmpty() && !isDotFile && !inHiddenParent -> HiddenArtifactCategory.UNUSUAL_NAMING_OR_STRUCTURE
            else -> HiddenArtifactCategory.DOT_PREFIXED_FILE_OR_DIR
        }

        val indexingEffect = when {
            isNoMedia -> "Suppresses Android MediaStore indexing for '$parentPath' and all child subdirectories; media files here will not appear in standard Gallery/Music apps."
            isDotFile || inHiddenParent -> "Hidden from standard user-facing gallery/file views due to leading dot prefix."
            isTrashFile -> "Pending deletion or recycle-bin artifact excluded from active MediaStore collections."
            else -> null
        }

        return HiddenArtifactFinding(
            path = abs,
            name = name,
            isDirectory = false,
            sizeBytes = sizeBytes,
            lastModifiedMs = lastModMs,
            lastModifiedIso = lastModIso,
            category = category,
            isNoMediaMarker = isNoMedia,
            affectedDirectoryPath = if (isNoMedia) parentPath else null,
            mediaIndexingEffect = indexingEffect,
            unusualIndicators = unusualIndicators,
            forensicNote = if (unusualIndicators.isNotEmpty()) {
                unusualIndicators.joinToString("; ")
            } else {
                category.defaultExplanation
            }
        )
    }

    data class EntropyAndAsciiSample(
        val shannonEntropy: Double,
        val printableAsciiRatio: Double
    )

    /**
     * Computes Shannon byte entropy (0.0 to 8.0 bits/byte) and printable ASCII ratio using
     * bounded 16 KB windows at the start, middle, and end of the file (max 48 KB read).
     */
    fun computeBoundedEntropyAndAsciiRatio(file: File, sizeBytes: Long = file.length()): EntropyAndAsciiSample {
        if (sizeBytes <= 0L || !file.exists()) return EntropyAndAsciiSample(0.0, 0.0)
        val counts = LongArray(256)
        var totalSampled = 0L
        var printableCount = 0L

        runCatching {
            RandomAccessFile(file, "r").use { raf ->
                val buf = ByteArray(ENTROPY_WINDOW_BYTES)
                val offsets = if (sizeBytes <= ENTROPY_WINDOW_BYTES * 2L) {
                    listOf(0L)
                } else {
                    listOf(
                        0L,
                        (sizeBytes / 2L).coerceAtLeast(0L),
                        (sizeBytes - ENTROPY_WINDOW_BYTES).coerceAtLeast(0L)
                    ).distinct()
                }
                for (offset in offsets) {
                    raf.seek(offset)
                    val read = raf.read(buf)
                    if (read > 0) {
                        for (i in 0 until read) {
                            val b = buf[i].toInt() and 0xFF
                            counts[b]++
                            if (b in 32..126 || b == 9 || b == 10 || b == 13) {
                                printableCount++
                            }
                        }
                        totalSampled += read
                    }
                }
            }
        }

        if (totalSampled <= 0L) return EntropyAndAsciiSample(0.0, 0.0)
        var entropy = 0.0
        val invTotal = 1.0 / totalSampled.toDouble()
        val ln2 = ln(2.0)
        for (c in counts) {
            if (c > 0L) {
                val p = c.toDouble() * invTotal
                entropy -= p * (ln(p) / ln2)
            }
        }
        val asciiRatio = printableCount.toDouble() * invTotal
        return EntropyAndAsciiSample(
            shannonEntropy = entropy.coerceIn(0.0, 8.0),
            printableAsciiRatio = asciiRatio.coerceIn(0.0, 1.0)
        )
    }

    /**
     * Inspects a file for technically verifiable encryption headers vs potential high-entropy indicators.
     */
    private fun inspectFileEncryption(
        file: File,
        fileName: String,
        declaredExt: String,
        sizeBytes: Long,
        lastModifiedIso: String?,
        header: ByteArray,
        magicHex16: String,
        entropy: Double,
        printableAsciiRatio: Double
    ): EncryptionFinding? {
        fun b(i: Int): Int = if (i < header.size) header[i].toInt() and 0xFF else -1

        // 1. Check ZIP local file header (50 4B 03 04) for encryption bit 0 or WinZip AES (compression method 99)
        if (header.size >= 10 && b(0) == 0x50 && b(1) == 0x4B && b(2) == 0x03 && b(3) == 0x04) {
            val gpFlags = (b(6) or (b(7) shl 8))
            val compMethod = (b(8) or (b(9) shl 8))
            val isBit0Encrypted = (gpFlags and 0x0001) != 0
            val isAesMethod = compMethod == 99
            if (isBit0Encrypted || isAesMethod) {
                val mech = if (isAesMethod) "ZIP WinZip AES-256 Encrypted Archive" else "ZIP Traditional PKWARE / AES Encrypted Archive"
                return EncryptionFinding(
                    path = file.absolutePath,
                    name = fileName,
                    declaredExtension = declaredExt,
                    sizeBytes = sizeBytes,
                    lastModifiedIso = lastModifiedIso,
                    verificationStatus = EncryptionVerificationStatus.CONFIRMED_FORMAT_HEADER,
                    detectedMechanism = mech,
                    technicalEvidence = "ZIP local header (50 4B 03 04) general-purpose flag=0x${gpFlags.toString(16).uppercase(Locale.US)} (bit 0 encrypted=$isBit0Encrypted), compressionMethod=$compMethod.",
                    shannonEntropyBitsPerByte = entropy,
                    magicHeaderHex = magicHex16,
                    limitationOrCaveat = "Entry filenames in the ZIP Central Directory remain readable, but payload streams require the archive password/key."
                )
            }
        }

        // 2. Check PDF header (%PDF-) for /Encrypt dictionary in header/tail
        if (header.size >= 5 && b(0) == 0x25 && b(1) == 0x50 && b(2) == 0x44 && b(3) == 0x46 && b(4) == 0x2D) {
            if (checkPdfHasEncryptDictionary(file, sizeBytes)) {
                return EncryptionFinding(
                    path = file.absolutePath,
                    name = fileName,
                    declaredExtension = declaredExt,
                    sizeBytes = sizeBytes,
                    lastModifiedIso = lastModifiedIso,
                    verificationStatus = EncryptionVerificationStatus.CONFIRMED_FORMAT_HEADER,
                    detectedMechanism = "PDF Standard / AES Security Handler (/Encrypt)",
                    technicalEvidence = "PDF trailer/object stream contains an explicit '/Encrypt' security handler dictionary.",
                    shannonEntropyBitsPerByte = entropy,
                    magicHeaderHex = magicHex16,
                    limitationOrCaveat = "PDF object streams are encrypted under a user/owner password security handler."
                )
            }
        }

        // 3. Check OpenSSL Salted__ magic header ("Salted__" = 53 61 6C 74 65 64 5F 5F)
        if (header.size >= 16 &&
            b(0) == 0x53 && b(1) == 0x61 && b(2) == 0x6C && b(3) == 0x74 &&
            b(4) == 0x65 && b(5) == 0x64 && b(6) == 0x5F && b(7) == 0x5F
        ) {
            val saltHex = header.sliceArray(8 until 16).joinToString("") { String.format(Locale.US, "%02x", it.toInt() and 0xFF) }
            return EncryptionFinding(
                path = file.absolutePath,
                name = fileName,
                declaredExtension = declaredExt,
                sizeBytes = sizeBytes,
                lastModifiedIso = lastModifiedIso,
                verificationStatus = EncryptionVerificationStatus.CONFIRMED_FORMAT_HEADER,
                detectedMechanism = "OpenSSL Salted Symmetric Ciphertext ('Salted__')",
                technicalEvidence = "Verified 8-byte ASCII magic 'Salted__' (53 61 6C 74 65 64 5F 5F) followed by 8-byte PBKDF salt ($saltHex).",
                shannonEntropyBitsPerByte = entropy,
                magicHeaderHex = magicHex16,
                limitationOrCaveat = "Cipher algorithm (AES-CBC, AES-256, etc.) is not stored in the OpenSSL header; decryption requires the passphrase and cipher parameter."
            )
        }

        // 4. Check LUKS partition/container header ("LUKS\xba\xbe" = 4C 55 4B 53 BA BE)
        if (header.size >= 8 &&
            b(0) == 0x4C && b(1) == 0x55 && b(2) == 0x4B && b(3) == 0x53 &&
            b(4) == 0xBA && b(5) == 0xBE
        ) {
            val version = (b(6) shl 8) or b(7)
            return EncryptionFinding(
                path = file.absolutePath,
                name = fileName,
                declaredExtension = declaredExt,
                sizeBytes = sizeBytes,
                lastModifiedIso = lastModifiedIso,
                verificationStatus = EncryptionVerificationStatus.CONFIRMED_FORMAT_HEADER,
                detectedMechanism = "LUKSv$version Encrypted Volume Container",
                technicalEvidence = "Verified LUKS magic signature (4C 55 4B 53 BA BE) with header version $version.",
                shannonEntropyBitsPerByte = entropy,
                magicHeaderHex = magicHex16,
                limitationOrCaveat = "Volume master key is protected by keyslots; payload cannot be inspected without key material."
            )
        }

        // 5. Check ASCII-armored PGP message header ("-----BEGIN PGP MESSAGE-----")
        val headerAscii = String(header, StandardCharsets.US_ASCII)
        if (headerAscii.startsWith("-----BEGIN PGP MESSAGE-----")) {
            return EncryptionFinding(
                path = file.absolutePath,
                name = fileName,
                declaredExtension = declaredExt,
                sizeBytes = sizeBytes,
                lastModifiedIso = lastModifiedIso,
                verificationStatus = EncryptionVerificationStatus.CONFIRMED_FORMAT_HEADER,
                detectedMechanism = "OpenPGP ASCII-Armored Encrypted Message",
                technicalEvidence = "File begins with RFC 4880 ASCII armor header '-----BEGIN PGP MESSAGE-----'.",
                shannonEntropyBitsPerByte = entropy,
                magicHeaderHex = magicHex16,
                limitationOrCaveat = "Requires recipient private key or symmetric passphrase to decrypt."
            )
        }

        // 6. Check OLE2 Compound Document (D0 CF 11 E0) for Office EncryptedPackage / EncryptionInfo
        if (header.size >= 8 && b(0) == 0xD0 && b(1) == 0xCF && b(2) == 0x11 && b(3) == 0xE0) {
            if (checkOle2HasEncryptedPackage(file, sizeBytes)) {
                return EncryptionFinding(
                    path = file.absolutePath,
                    name = fileName,
                    declaredExtension = declaredExt,
                    sizeBytes = sizeBytes,
                    lastModifiedIso = lastModifiedIso,
                    verificationStatus = EncryptionVerificationStatus.CONFIRMED_FORMAT_HEADER,
                    detectedMechanism = "Microsoft Office Encrypted Package (OLE2 Agile/Standard)",
                    technicalEvidence = "OLE2 container (D0 CF 11 E0) contains 'EncryptedPackage' / 'EncryptionInfo' stream directory markers.",
                    shannonEntropyBitsPerByte = entropy,
                    magicHeaderHex = magicHex16,
                    limitationOrCaveat = "OOXML document streams are encrypted inside an OLE2 wrapper."
                )
            }
        }

        // 7. Check RAR v5 (52 61 72 21 1A 07 01 00) or RAR v4 (52 61 72 21 1A 07 00) encrypted header flag
        if (header.size >= 14 && b(0) == 0x52 && b(1) == 0x61 && b(2) == 0x72 && b(3) == 0x21 && b(4) == 0x1A && b(5) == 0x07) {
            val isRar5 = b(6) == 0x01 && b(7) == 0x00
            val isRar4Encrypted = !isRar5 && ((b(10) or (b(11) shl 8)) and 0x0080) != 0
            if (isRar4Encrypted) {
                return EncryptionFinding(
                    path = file.absolutePath,
                    name = fileName,
                    declaredExtension = declaredExt,
                    sizeBytes = sizeBytes,
                    lastModifiedIso = lastModifiedIso,
                    verificationStatus = EncryptionVerificationStatus.CONFIRMED_FORMAT_HEADER,
                    detectedMechanism = "RAR Archive Header Encryption",
                    technicalEvidence = "RAR archive header flag bit 0x0080 (MHD_PASSWORD) is set.",
                    shannonEntropyBitsPerByte = entropy,
                    magicHeaderHex = magicHex16,
                    limitationOrCaveat = "Both archive headers and file data are encrypted."
                )
            }
        }

        // 8. Check known compressed media/archive formats so we DO NOT misclassify them as encrypted
        val sig = detectSignatureAndFormat(header, fileName, declaredExt)
        if (sig.detectedFormat != "UNKNOWN" && sig.detectedFormat != "TEXT_ASCII") {
            if (entropy >= 7.20) {
                return EncryptionFinding(
                    path = file.absolutePath,
                    name = fileName,
                    declaredExtension = declaredExt,
                    sizeBytes = sizeBytes,
                    lastModifiedIso = lastModifiedIso,
                    verificationStatus = EncryptionVerificationStatus.COMPRESSED_MEDIA_NOT_ENCRYPTED,
                    detectedMechanism = "Standard Compressed Container (${sig.detectedFormat})",
                    technicalEvidence = "Verified unencrypted ${sig.detectedFormat} header ($magicHex16); high entropy (${String.format(Locale.US, "%.2f", entropy)} bits/byte) is expected for compressed media/archive streams.",
                    shannonEntropyBitsPerByte = entropy,
                    magicHeaderHex = magicHex16,
                    limitationOrCaveat = "Not encrypted; high byte entropy results from standard lossless/lossy compression."
                )
            }
            return null
        }

        // 9. Potential Encryption Indicator:
        // Unidentified binary format + high Shannon entropy (>= 7.80 bits/byte) OR explicit encrypted extension with high entropy (>= 7.0 bits/byte)
        val hasEncryptedExtension = declaredExt in KNOWN_ENCRYPTED_EXTS
        val isHighEntropyUnknownBlob = sizeBytes >= 256L && printableAsciiRatio < 0.60 && entropy >= 7.80
        if ((hasEncryptedExtension && entropy >= 7.0 && sizeBytes >= 64L) || isHighEntropyUnknownBlob) {
            val mechanism = if (hasEncryptedExtension) {
                "Encrypted Extension (.$declaredExt) with High-Entropy Payload"
            } else {
                "Unclassified High-Entropy Binary Stream"
            }
            return EncryptionFinding(
                path = file.absolutePath,
                name = fileName,
                declaredExtension = declaredExt.ifBlank { "(none)" },
                sizeBytes = sizeBytes,
                lastModifiedIso = lastModifiedIso,
                verificationStatus = EncryptionVerificationStatus.POTENTIAL_HIGH_ENTROPY_INDICATOR,
                detectedMechanism = mechanism,
                technicalEvidence = "Shannon byte entropy = ${String.format(Locale.US, "%.3f", entropy)} / 8.000 bits/byte, printable ASCII ratio = ${String.format(Locale.US, "%.1f", printableAsciiRatio * 100)}%, no known cleartext container magic ($magicHex16).",
                shannonEntropyBitsPerByte = entropy,
                magicHeaderHex = magicHex16,
                limitationOrCaveat = "Statistical high entropy indicates pseudo-random byte distribution consistent with either headerless encryption (e.g., raw AES/ChaCha20, SQLCipher) or raw compressed binary data; it is not standalone proof of encryption."
            )
        }

        return null
    }

    private fun checkPdfHasEncryptDictionary(file: File, sizeBytes: Long): Boolean = runCatching {
        RandomAccessFile(file, "r").use { raf ->
            val headSize = min(16 * 1024L, sizeBytes).toInt()
            val headBytes = ByteArray(headSize)
            raf.readFully(headBytes)
            val headStr = String(headBytes, StandardCharsets.ISO_8859_1)
            if (headStr.contains("/Encrypt")) return@use true

            if (sizeBytes > headSize) {
                val tailSize = min(32 * 1024L, sizeBytes).toInt()
                raf.seek(sizeBytes - tailSize)
                val tailBytes = ByteArray(tailSize)
                raf.readFully(tailBytes)
                val tailStr = String(tailBytes, StandardCharsets.ISO_8859_1)
                if (tailStr.contains("/Encrypt")) return@use true
            }
            false
        }
    }.getOrDefault(false)

    private fun checkOle2HasEncryptedPackage(file: File, sizeBytes: Long): Boolean = runCatching {
        RandomAccessFile(file, "r").use { raf ->
            val scanLen = min(64 * 1024L, sizeBytes).toInt()
            val buf = ByteArray(scanLen)
            raf.readFully(buf)
            val latin = String(buf, StandardCharsets.ISO_8859_1)
            val utf16 = String(buf, StandardCharsets.UTF_16LE)
            latin.contains("EncryptedPackage") || latin.contains("EncryptionInfo") ||
                utf16.contains("EncryptedPackage") || utf16.contains("EncryptionInfo")
        }
    }.getOrDefault(false)

    private data class SignatureCheckResult(
        val detectedFormat: String,
        val detectedMime: String,
        val category: String?,
        val isMismatch: Boolean,
        val mismatchExplanation: String?
    )

    private fun detectSignatureAndFormat(
        header: ByteArray,
        fileName: String,
        declaredExt: String
    ): SignatureCheckResult {
        fun b(i: Int): Int = if (i < header.size) header[i].toInt() and 0xFF else -1

        var format = "UNKNOWN"
        var mime = "application/octet-stream"
        var cat: String? = null
        var expectedExts = emptySet<String>()

        when {
            header.size >= 3 && b(0) == 0xFF && b(1) == 0xD8 && b(2) == 0xFF -> {
                format = "JPEG"
                mime = "image/jpeg"
                cat = "PHOTO"
                expectedExts = setOf("jpg", "jpeg", "jfif", "thumb", "0", "1", "2")
            }
            header.size >= 8 && b(0) == 0x89 && b(1) == 0x50 && b(2) == 0x4E && b(3) == 0x47 -> {
                format = "PNG"
                mime = "image/png"
                cat = "PHOTO"
                expectedExts = setOf("png")
            }
            header.size >= 6 && b(0) == 0x47 && b(1) == 0x49 && b(2) == 0x46 && b(3) == 0x38 -> {
                format = "GIF"
                mime = "image/gif"
                cat = "PHOTO"
                expectedExts = setOf("gif")
            }
            header.size >= 12 && b(0) == 0x52 && b(1) == 0x49 && b(2) == 0x46 && b(3) == 0x46 -> {
                val sub = String(header, 8, 4, StandardCharsets.US_ASCII)
                when (sub) {
                    "WEBP" -> {
                        format = "WEBP"
                        mime = "image/webp"
                        cat = "PHOTO"
                        expectedExts = setOf("webp")
                    }
                    "WAVE" -> {
                        format = "WAV"
                        mime = "audio/wav"
                        cat = "AUDIO"
                        expectedExts = setOf("wav")
                    }
                    "AVI " -> {
                        format = "AVI"
                        mime = "video/x-msvideo"
                        cat = "VIDEO"
                        expectedExts = setOf("avi")
                    }
                }
            }
            header.size >= 12 && b(4) == 0x66 && b(5) == 0x74 && b(6) == 0x79 && b(7) == 0x70 -> {
                val brand = String(header, 8, 4, StandardCharsets.US_ASCII).lowercase(Locale.US)
                when {
                    brand.startsWith("hei") || brand.startsWith("mif") || brand.startsWith("avi") -> {
                        format = "HEIC/AVIF"
                        mime = "image/heic"
                        cat = "PHOTO"
                        expectedExts = setOf("heic", "heif", "avif")
                    }
                    brand.startsWith("m4a") || brand.startsWith("m4b") -> {
                        format = "M4A"
                        mime = "audio/mp4"
                        cat = "AUDIO"
                        expectedExts = setOf("m4a", "m4b", "aac", "mp4")
                    }
                    else -> {
                        format = "MP4/ISOBMFF"
                        mime = "video/mp4"
                        cat = "VIDEO"
                        expectedExts = setOf("mp4", "mov", "3gp", "3g2", "m4v")
                    }
                }
            }
            header.size >= 4 && b(0) == 0x1A && b(1) == 0x45 && b(2) == 0xDF && b(3) == 0xA3 -> {
                format = "MKV/WEBM"
                mime = "video/x-matroska"
                cat = "VIDEO"
                expectedExts = setOf("mkv", "webm", "mka")
            }
            header.size >= 4 && b(0) == 0x25 && b(1) == 0x50 && b(2) == 0x44 && b(3) == 0x46 -> {
                format = "PDF"
                mime = "application/pdf"
                cat = "DOCUMENT_ARCHIVE"
                expectedExts = setOf("pdf")
            }
            header.size >= 4 && b(0) == 0x50 && b(1) == 0x4B && b(2) == 0x03 && b(3) == 0x04 -> {
                format = "ZIP_CONTAINER"
                mime = "application/zip"
                cat = if (declaredExt in setOf("apk", "xapk", "apks", "jar", "aab")) "PACKAGE_BINARY" else "DOCUMENT_ARCHIVE"
                expectedExts = setOf("zip", "apk", "xapk", "apks", "jar", "aab", "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub")
            }
            header.size >= 16 && String(header, 0, 15, StandardCharsets.US_ASCII) == "SQLite format 3" -> {
                format = "SQLITE3"
                mime = "application/vnd.sqlite3"
                cat = "DATABASE"
                expectedExts = setOf("db", "sqlite", "sqlite3", "db3")
            }
            header.size >= 4 && b(0) == 0x7F && b(1) == 0x45 && b(2) == 0x4C && b(3) == 0x46 -> {
                format = "ELF_BINARY"
                mime = "application/x-elf"
                cat = "PACKAGE_BINARY"
                expectedExts = setOf("so", "elf", "bin", "")
            }
            header.size >= 4 && b(0) == 0x64 && b(1) == 0x65 && b(2) == 0x78 && b(3) == 0x0A -> {
                format = "ANDROID_DEX"
                mime = "application/octet-stream"
                cat = "PACKAGE_BINARY"
                expectedExts = setOf("dex", "odex")
            }
            header.size >= 4 && b(0) == 0x52 && b(1) == 0x61 && b(2) == 0x72 && b(3) == 0x21 -> {
                format = "RAR"
                mime = "application/vnd.rar"
                cat = "DOCUMENT_ARCHIVE"
                expectedExts = setOf("rar")
            }
            header.size >= 4 && b(0) == 0x37 && b(1) == 0x7A && b(2) == 0xBC && b(3) == 0xAF -> {
                format = "7Z"
                mime = "application/x-7z-compressed"
                cat = "DOCUMENT_ARCHIVE"
                expectedExts = setOf("7z")
            }
            header.size >= 3 && ((b(0) == 0x49 && b(1) == 0x44 && b(2) == 0x33) || (b(0) == 0xFF && (b(1) == 0xFB || b(1) == 0xF3 || b(1) == 0xF2))) -> {
                format = "MP3"
                mime = "audio/mpeg"
                cat = "AUDIO"
                expectedExts = setOf("mp3")
            }
            header.size >= 4 && b(0) == 0x66 && b(1) == 0x4C && b(2) == 0x61 && b(3) == 0x43 -> {
                format = "FLAC"
                mime = "audio/flac"
                cat = "AUDIO"
                expectedExts = setOf("flac")
            }
            header.size >= 4 && b(0) == 0x4F && b(1) == 0x67 && b(2) == 0x67 && b(3) == 0x53 -> {
                format = "OGG"
                mime = "audio/ogg"
                cat = "AUDIO"
                expectedExts = setOf("ogg", "opus", "ogv")
            }
        }

        // Check if declared extension contradicts the verified binary header
        val genericExts = setOf("", "tmp", "temp", "cache", "bin", "dat", "bak", "old")
        val isMismatch = format != "UNKNOWN" &&
            declaredExt !in genericExts &&
            expectedExts.isNotEmpty() &&
            declaredExt !in expectedExts

        val mismatchExplanation = if (isMismatch) {
            "File '$fileName' has declared extension '.$declaredExt', but its binary magic header matches $format ($mime)."
        } else {
            null
        }

        return SignatureCheckResult(
            detectedFormat = format,
            detectedMime = mime,
            category = cat,
            isMismatch = isMismatch,
            mismatchExplanation = mismatchExplanation
        )
    }

    private fun buildAsciiPreview(bytes: ByteArray): String {
        val sb = StringBuilder()
        val limit = min(bytes.size, 24)
        for (i in 0 until limit) {
            val c = bytes[i].toInt() and 0xFF
            sb.append(if (c in 32..126) c.toChar() else '.')
        }
        return sb.toString()
    }

    private fun buildInaccessibleAreasList(
        hasAllFilesAccess: Boolean,
        environmentAssessment: DeviceEnvironmentAssessment?,
        encounteredUnreadablePaths: List<String>
    ): List<InaccessibleStorageArea> {
        val list = ArrayList<InaccessibleStorageArea>()
        val rootVerified = environmentAssessment?.rootShellVerifiedUid0 == true

        if (!hasAllFilesAccess) {
            list.add(
                InaccessibleStorageArea(
                    path = "/storage/emulated/0 (Non-Media Directories)",
                    areaType = "Shared External Storage",
                    restrictionReason = "All Files Access (MANAGE_EXTERNAL_STORAGE) is not currently granted.",
                    securityMechanism = "Android Scoped Storage",
                    canBeAccessedViaSafOrPermission = true,
                    forensicImpact = "DeepVault can only inspect app-local storage or user-selected SAF directories until storage permission is granted."
                )
            )
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && !rootVerified) {
            list.add(
                InaccessibleStorageArea(
                    path = "/storage/emulated/0/Android/data & /Android/obb",
                    areaType = "External App Sandbox Directories",
                    restrictionReason = "Android 11+ (API 30+) blocks cross-app enumeration of /Android/data and /Android/obb even when MANAGE_EXTERNAL_STORAGE is granted.",
                    securityMechanism = "Scoped Storage & FUSE Mount Isolation",
                    canBeAccessedViaSafOrPermission = false,
                    forensicImpact = "Third-party app external caches and OBB containers cannot be enumerated without ADB or verified root privileges."
                )
            )
        }

        if (!rootVerified) {
            list.add(
                InaccessibleStorageArea(
                    path = "/data/data/<package_name> & /data/user/0/<package_name>",
                    areaType = "Internal Application Sandboxes",
                    restrictionReason = "Each Android app runs under a dedicated Linux UID with mode 0700 directory isolation.",
                    securityMechanism = "Linux DAC + SELinux App Sandbox",
                    canBeAccessedViaSafOrPermission = false,
                    forensicImpact = "Private SQLite databases, internal shared_prefs, and private keystores of other apps cannot be inspected."
                )
            )
        }

        list.add(
            InaccessibleStorageArea(
                path = "/dev/block/by-name/userdata (Unallocated Filesystem Blocks)",
                areaType = "Raw Block Device & Unallocated Space",
                restrictionReason = "Direct block device reads are blocked by SELinux and encrypted per-file by hardware-backed File-Based Encryption (FBE).",
                securityMechanism = "SELinux Enforcing + Hardware FBE + Flash TRIM",
                canBeAccessedViaSafOrPermission = false,
                forensicImpact = "Deleted files whose filesystem inodes and FBE per-file inline encryption keys have been wiped cannot be carved from raw blocks."
            )
        )

        encounteredUnreadablePaths.take(10).forEach { p ->
            if (list.none { it.path == p }) {
                list.add(
                    InaccessibleStorageArea(
                        path = p,
                        areaType = "Encountered Restricted Directory",
                        restrictionReason = "Directory returned permission denied (canRead=false or null listing) during traversal.",
                        securityMechanism = "Filesystem Permissions / SELinux",
                        canBeAccessedViaSafOrPermission = p.startsWith("/storage/emulated/0"),
                        forensicImpact = "Contents of this directory were excluded from scan coverage totals."
                    )
                )
            }
        }

        return list
    }
}

fun formatBytesHuman(bytes: Long): String {
    if (bytes <= 0L) return "0 B"
    val units = arrayOf("B", "KB", "MB", "GB", "TB")
    var value = bytes.toDouble()
    var unitIdx = 0
    while (value >= 1024.0 && unitIdx < units.lastIndex) {
        value /= 1024.0
        unitIdx++
    }
    return if (unitIdx == 0) {
        "$bytes B"
    } else {
        String.format(Locale.US, "%.2f %s", value, units[unitIdx])
    }
}
