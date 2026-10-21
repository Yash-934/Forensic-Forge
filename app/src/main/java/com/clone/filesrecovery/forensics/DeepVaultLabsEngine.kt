package com.clone.filesrecovery.forensics

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.graphics.BitmapFactory
import com.clone.filesrecovery.data.FileCategory
import com.clone.filesrecovery.data.RecoverableFile
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream
import kotlin.math.min

/**
 * Explicit 6-state Recovery Classification required by Section 4.
 */
enum class RecoveryClassification(
    val code: String,
    val title: String,
    val description: String
) {
    RECOVERED(
        code = "RECOVERED",
        title = "Recovered (Validated)",
        description = "Output exists and passes applicable header, footer, and structural validation checks."
    ),
    PARTIALLY_RECOVERED(
        code = "PARTIALLY_RECOVERED",
        title = "Partially Recovered",
        description = "Usable header and partial payload bytes exist, but trailer/completeness could not be established."
    ),
    IDENTIFIED_ONLY(
        code = "IDENTIFIED_ONLY",
        title = "Identified Only",
        description = "Metadata or index reference to a file exists, but usable payload bytes were not recoverable."
    ),
    CORRUPTED(
        code = "CORRUPTED",
        title = "Corrupted",
        description = "Recovered or inspected bytes fail applicable format integrity, chunk, or header/footer checks."
    ),
    UNVERIFIED(
        code = "UNVERIFIED",
        title = "Unverified",
        description = "File bytes were extracted, but format-specific structural validation is not available for this type."
    ),
    FAILED(
        code = "FAILED",
        title = "Failed",
        description = "The recovery or extraction attempt failed due to unreadable source or I/O restriction."
    )
}

/**
 * Fragmentation awareness assessment for a file or carved stream.
 */
data class FragmentationAssessment(
    val isSupportedOnSource: Boolean,
    val statusLabel: String,
    val contiguousLikelihood: String,
    val notes: String
)

/**
 * Deep File Structure Analysis result (Section 5.D).
 */
data class FileStructureAnalysis(
    val filePath: String,
    val fileName: String,
    val fileSize: Long,
    val recognizedSignatureHex: String,
    val detectedFormat: String,
    val expectedStructureSummary: String,
    val headerValid: Boolean,
    val footerValid: Boolean?,
    val headerDetail: String,
    val footerDetail: String,
    val isTruncated: Boolean,
    val truncationIndicators: List<String>,
    val unexpectedTrailingBytes: Long,
    val trailingDataNote: String?,
    val structuralErrors: List<String>,
    val chunksOrBoxesSummary: List<String>,
    val recoveryClassification: RecoveryClassification,
    val fragmentationAssessment: FragmentationAssessment,
    val neutralAdvisory: String = "Structural anomalies, truncation, or trailing bytes can result from interrupted writes, caching, app appendages, or partial carving and do not by themselves prove malicious intent."
)

/**
 * Carved stream candidate from an accessible raw image, cache blob, or byte stream (Section 4).
 */
data class CarvedStreamResult(
    val index: Int,
    val format: String,
    val extension: String,
    val startOffset: Long,
    val endOffsetExclusive: Long,
    val lengthBytes: Long,
    val outputFile: File?,
    val sha256: String?,
    val classification: RecoveryClassification,
    val validationSummary: String,
    val fragmentationNote: String
)

/**
 * Streaming read-only Hex Viewer page model (Section 5.C).
 */
data class HexViewerPage(
    val filePath: String,
    val fileName: String,
    val totalFileSize: Long,
    val pageOffset: Long,
    val pageLength: Int,
    val rows: List<HexRow>,
    val signatureHighlightRange: LongRange?,
    val signatureDescription: String
)

data class HexRow(
    val offset: Long,
    val offsetHex: String,
    val hexBytes: List<String>,
    val asciiText: String,
    val highlightedByteIndices: Set<Int> = emptySet()
)

data class HexSearchMatch(
    val offset: Long,
    val offsetHex: String,
    val matchedBytesHex: String,
    val contextAscii: String
)

/**
 * Multi-strategy Duplicate Classification (Section 5.E).
 */
enum class DuplicateMatchStrategy(val code: String, val label: String, val explanation: String) {
    EXACT_SHA256(
        code = "EXACT_BYTE_DUPLICATE",
        label = "Exact Byte Duplicate (SHA-256)",
        explanation = "Files have identical byte length and matching cryptographic SHA-256 digests."
    ),
    PERCEPTUAL_SIMILAR_IMAGE(
        code = "VISUALLY_SIMILAR_IMAGE",
        label = "Visually Similar Image (dHash)",
        explanation = "Images have different byte hashes (e.g., recompressed or resized) but closely matching 64-bit difference hashes."
    ),
    SAME_SIZE_UNPROVEN(
        code = "SAME_SIZE_DIFFERENT_CONTENT",
        label = "Same Byte Size (Not Identical)",
        explanation = "Files share the exact same byte size on disk, but their SHA-256 digests differ."
    )
}

data class MultiStrategyDuplicateCluster(
    val clusterId: String,
    val strategy: DuplicateMatchStrategy,
    val signatureOrSizeKey: String,
    val files: List<DuplicateMemberItem>
)

data class DuplicateMemberItem(
    val path: String,
    val name: String,
    val sizeBytes: Long,
    val sha256: String,
    val dHashHex: String? = null
)

/**
 * Deterministic File Relationship item (Section 5.F).
 */
enum class RelationshipType(val label: String, val isProvenFact: Boolean) {
    IDENTICAL_SHA256_CONTENT("Identical SHA-256 Byte Content", true),
    THUMBNAIL_TO_PARENT_MEDIA("Thumbnail to Parent Media Correlation", false),
    SHARED_CAMERA_OR_AUTHOR_METADATA("Shared Camera Model / Document Author Metadata", false),
    SHARED_ACCESSIBLE_DIRECTORY("Shared Accessible Source Directory", true),
    ARCHIVE_CONTAINMENT("Archive Entry / Container Association", true),
    CASE_BOOKMARK_ASSOCIATION("Analyst Case Association", true)
}

data class FileRelationshipEdge(
    val relationshipId: String,
    val sourceFileName: String,
    val sourcePath: String,
    val targetFileName: String,
    val targetPath: String,
    val relationshipType: RelationshipType,
    val evidenceBasis: String,
    val confidenceNote: String
)

/**
 * Archive Forensics inspection report (Section 5.G).
 */
data class ArchiveForensicEntry(
    val index: Int,
    val entryName: String,
    val isDirectory: Boolean,
    val compressedSize: Long,
    val uncompressedSize: Long,
    val compressionMethod: String,
    val compressionRatio: Double,
    val crc32Hex: String,
    val sha256: String?,
    val lastModifiedIso: String?,
    val hasPathTraversalAnomaly: Boolean,
    val hasHighCompressionRatioAnomaly: Boolean
)

data class ArchiveForensicReport(
    val archivePath: String,
    val archiveName: String,
    val fileSize: Long,
    val sha256: String,
    val structureValid: Boolean,
    val hasEndOfCentralDirectory: Boolean,
    val isTruncatedOrCorrupted: Boolean,
    val totalEntries: Int,
    val entries: List<ArchiveForensicEntry>,
    val structuralAnomalies: List<String>,
    val safetyNote: String = "Archive contents were inspected strictly via passive stream/header parsing and were never extracted to disk or executed."
)

/**
 * SQLite Forensics inspection report (Section 5.H).
 */
data class SqliteTableSchema(
    val name: String,
    val type: String, // "table" or "index" or "view"
    val sql: String,
    val liveRowCount: Long,
    val sampleRows: List<Map<String, String>>
)

data class SqliteUnallocatedRemnant(
    val pageNumber: Int,
    val byteOffset: Long,
    val sourceRegion: String, // "freelist_or_freeblock" or "unallocated_cell_gap"
    val extractedAsciiStrings: List<String>
)

data class SqliteForensicReport(
    val dbPath: String,
    val dbName: String,
    val fileSize: Long,
    val sha256: String,
    val isValidSqliteHeader: Boolean,
    val sqliteVersionString: String,
    val pageSizeBytes: Int,
    val totalPagesInHeader: Long,
    val textEncoding: String,
    val freelistTrunkPage: Long,
    val freelistPageCount: Long,
    val fileChangeCounter: Long,
    val integrityCheckResult: String,
    val walFilePresent: Boolean,
    val walFileSizeBytes: Long,
    val journalFilePresent: Boolean,
    val journalFileSizeBytes: Long,
    val tables: List<SqliteTableSchema>,
    val indexes: List<String>,
    val unallocatedRemnants: List<SqliteUnallocatedRemnant>,
    val limitations: List<String>
)

/**
 * Media Thumbnail Explorer item (Section 5.I).
 */
data class ThumbnailForensicItem(
    val thumbnailPath: String,
    val thumbnailName: String,
    val sourceOrigin: String,
    val sizeBytes: Long,
    val sha256: String,
    val width: Int,
    val height: Int,
    val matchedParentMediaPath: String?,
    val matchedParentMediaName: String?,
    val relationshipBasis: String,
    val recoveryClassification: RecoveryClassification,
    val limitationsNote: String
)

/**
 * File Repair Lab result (Section 6).
 */
enum class FileRepairOutcome(val label: String) {
    REPAIRED_CONTAINER_VALIDATED("Repaired & Validated (New Copy Created)"),
    PARTIAL_REPAIR_WARNING("Header/Trailer Reconstructed (Payload Incomplete)"),
    NO_REPAIR_NEEDED("File Structure Already Valid (No Repair Needed)"),
    REPAIR_UNSUPPORTED_OR_FAILED("Repair Unsupported or Insufficient Source Data")
}

data class FileRepairReport(
    val originalPath: String,
    val originalName: String,
    val originalSize: Long,
    val originalSha256: String,
    val detectedFormat: String,
    val diagnosisBefore: FileStructureAnalysis,
    val repairMethodApplied: String,
    val repairOutcome: FileRepairOutcome,
    val repairedOutputFile: File?,
    val repairedSize: Long?,
    val repairedSha256: String?,
    val validationAfter: FileStructureAnalysis?,
    val warnings: List<String>,
    val honestDisclosure: String
)

/**
 * Unified deterministic engine for DeepVault's Advanced Forensics Lab, Signature Carving,
 * Format-Aware Reconstruction, Hex Viewer, Archive/SQLite Forensics, and File Repair Lab.
 */
object DeepVaultLabsEngine {

    private const val STREAM_CHUNK = 64 * 1024

    // =========================================================================
    // 1. READ-ONLY STREAMING HEX VIEWER & PATTERN SEARCH (Section 5.C)
    // =========================================================================

    fun readHexPage(
        file: File,
        pageOffset: Long,
        bytesPerPage: Int = 512,
        bytesPerRow: Int = 16
    ): HexViewerPage {
        if (!file.exists() || !file.isFile || !file.canRead()) {
            return HexViewerPage(
                filePath = file.absolutePath,
                fileName = file.name,
                totalFileSize = 0L,
                pageOffset = 0L,
                pageLength = 0,
                rows = emptyList(),
                signatureHighlightRange = null,
                signatureDescription = "File unreadable or missing"
            )
        }
        val totalSize = file.length()
        val safeOffset = pageOffset.coerceIn(0L, maxOf(0L, totalSize - 1L))
        val toRead = min(bytesPerPage.toLong(), maxOf(0L, totalSize - safeOffset)).toInt()
        val buffer = ByteArray(toRead)

        RandomAccessFile(file, "r").use { raf ->
            raf.seek(safeOffset)
            var readSoFar = 0
            while (readSoFar < toRead) {
                val n = raf.read(buffer, readSoFar, toRead - readSoFar)
                if (n <= 0) break
                readSoFar += n
            }
        }

        // Identify magic signature range in the first 16 bytes for highlighting
        val (sigRange, sigDesc) = detectMagicSignatureRange(file)

        val rows = mutableListOf<HexRow>()
        var idx = 0
        while (idx < toRead) {
            val rowEnd = min(idx + bytesPerRow, toRead)
            val rowAbsOffset = safeOffset + idx
            val hexList = mutableListOf<String>()
            val asciiSb = StringBuilder()
            val highlights = mutableSetOf<Int>()

            for (bIdx in idx until rowEnd) {
                val b = buffer[bIdx].toInt() and 0xFF
                hexList.add(String.format(Locale.US, "%02X", b))
                val ch = if (b in 32..126) b.toChar() else '.'
                asciiSb.append(ch)
                val absByteOffset = safeOffset + bIdx
                if (sigRange != null && absByteOffset in sigRange) {
                    highlights.add(bIdx - idx)
                }
            }
            rows.add(
                HexRow(
                    offset = rowAbsOffset,
                    offsetHex = String.format(Locale.US, "%08X", rowAbsOffset),
                    hexBytes = hexList,
                    asciiText = asciiSb.toString(),
                    highlightedByteIndices = highlights
                )
            )
            idx += bytesPerRow
        }

        return HexViewerPage(
            filePath = file.absolutePath,
            fileName = file.name,
            totalFileSize = totalSize,
            pageOffset = safeOffset,
            pageLength = toRead,
            rows = rows,
            signatureHighlightRange = sigRange,
            signatureDescription = sigDesc
        )
    }

    /**
     * Searches a file in streaming 64 KB chunks for either a hex byte sequence (e.g. "FF D8 FF" or "89504E47")
     * or an ASCII string without loading the entire file into memory.
     */
    suspend fun searchBytePatternStreaming(
        file: File,
        query: String,
        isHexQuery: Boolean,
        maxMatches: Int = 50
    ): List<HexSearchMatch> = withContext(Dispatchers.IO) {
        if (!file.exists() || !file.isFile || !file.canRead() || query.isBlank()) {
            return@withContext emptyList()
        }
        val needle: ByteArray = if (isHexQuery) {
            val cleaned = query.replace(" ", "").replace("0x", "", ignoreCase = true).trim()
            if (cleaned.length < 2 || cleaned.length % 2 != 0) return@withContext emptyList()
            runCatching {
                ByteArray(cleaned.length / 2) { i ->
                    cleaned.substring(i * 2, i * 2 + 2).toInt(16).toByte()
                }
            }.getOrNull() ?: return@withContext emptyList()
        } else {
            query.toByteArray(StandardCharsets.UTF_8)
        }

        if (needle.isEmpty() || needle.size > 1024) return@withContext emptyList()

        val matches = mutableListOf<HexSearchMatch>()
        val overlap = needle.size - 1
        val buffer = ByteArray(STREAM_CHUNK + overlap)
        var filePos = 0L
        var carryBytes = 0

        FileInputStream(file).use { fis ->
            while (matches.size < maxMatches) {
                currentCoroutineContext().ensureActive()
                val n = fis.read(buffer, carryBytes, STREAM_CHUNK)
                if (n <= 0) break
                val validLen = carryBytes + n
                val limit = validLen - needle.size
                var i = 0
                while (i <= limit && matches.size < maxMatches) {
                    var ok = true
                    for (j in needle.indices) {
                        if (buffer[i + j] != needle[j]) {
                            ok = false
                            break
                        }
                    }
                    if (ok) {
                        val absOffset = filePos - carryBytes + i
                        val ctxEnd = min(validLen, i + min(needle.size + 12, 24))
                        val slice = buffer.copyOfRange(i, ctxEnd)
                        val hexStr = slice.take(needle.size).joinToString(" ") {
                            String.format(Locale.US, "%02X", it.toInt() and 0xFF)
                        }
                        val asciiCtx = buildString {
                            for (b in slice) {
                                val v = b.toInt() and 0xFF
                                append(if (v in 32..126) v.toChar() else '.')
                            }
                        }
                        matches.add(
                            HexSearchMatch(
                                offset = absOffset,
                                offsetHex = String.format(Locale.US, "0x%08X", absOffset),
                                matchedBytesHex = hexStr,
                                contextAscii = asciiCtx
                            )
                        )
                    }
                    i++
                }
                filePos += n
                if (overlap > 0 && validLen >= overlap) {
                    System.arraycopy(buffer, validLen - overlap, buffer, 0, overlap)
                    carryBytes = overlap
                } else {
                    carryBytes = 0
                }
            }
        }
        matches
    }

    private fun detectMagicSignatureRange(file: File): Pair<LongRange?, String> {
        if (!file.exists() || file.length() == 0L) return null to "Empty file"
        val head = ByteArray(min(32L, file.length()).toInt())
        runCatching {
            FileInputStream(file).use { it.read(head) }
        }
        if (head.size >= 3 && (head[0].toInt() and 0xFF) == 0xFF && (head[1].toInt() and 0xFF) == 0xD8 && (head[2].toInt() and 0xFF) == 0xFF) {
            return (0L..2L) to "JPEG SOI Magic (FF D8 FF)"
        }
        if (head.size >= 8 &&
            (head[0].toInt() and 0xFF) == 0x89 && head[1] == 0x50.toByte() &&
            head[2] == 0x4E.toByte() && head[3] == 0x47.toByte()
        ) {
            return (0L..7L) to "PNG 8-Byte Signature (89 50 4E 47 0D 0A 1A 0A)"
        }
        if (head.size >= 12 &&
            head[0] == 'R'.code.toByte() && head[1] == 'I'.code.toByte() &&
            head[2] == 'F'.code.toByte() && head[3] == 'F'.code.toByte() &&
            head[8] == 'W'.code.toByte() && head[9] == 'E'.code.toByte() &&
            head[10] == 'B'.code.toByte() && head[11] == 'P'.code.toByte()
        ) {
            return (0L..11L) to "RIFF WebP Container Signature"
        }
        if (head.size >= 5 &&
            head[0] == '%'.code.toByte() && head[1] == 'P'.code.toByte() &&
            head[2] == 'D'.code.toByte() && head[3] == 'F'.code.toByte() && head[4] == '-'.code.toByte()
        ) {
            return (0L..7L) to "PDF Header Signature (%PDF-1.x)"
        }
        if (head.size >= 4 &&
            head[0] == 'P'.code.toByte() && head[1] == 'K'.code.toByte() &&
            head[2] == 0x03.toByte() && head[3] == 0x04.toByte()
        ) {
            return (0L..3L) to "ZIP Local File Header (50 4B 03 04)"
        }
        if (head.size >= 16 && String(head, 0, 15, StandardCharsets.US_ASCII) == "SQLite format 3") {
            return (0L..15L) to "SQLite 3 Database Header (SQLite format 3\\0)"
        }
        if (head.size >= 8 &&
            head[4] == 'f'.code.toByte() && head[5] == 't'.code.toByte() &&
            head[6] == 'y'.code.toByte() && head[7] == 'p'.code.toByte()
        ) {
            return (0L..11L) to "ISO Base Media File Format (ftyp box)"
        }
        return (0L..min(3L, head.lastIndex.toLong())) to "Initial Header Bytes"
    }

    // =========================================================================
    // 2. DEEP FILE STRUCTURE ANALYZER & TRAILING DATA INSPECTOR (Section 4 & 5.D)
    // =========================================================================

    fun analyzeFileStructure(file: File): FileStructureAnalysis {
        if (!file.exists() || !file.isFile || !file.canRead()) {
            return FileStructureAnalysis(
                filePath = file.absolutePath,
                fileName = file.name,
                fileSize = 0L,
                recognizedSignatureHex = "",
                detectedFormat = "UNREADABLE",
                expectedStructureSummary = "Readable byte stream required",
                headerValid = false,
                footerValid = false,
                headerDetail = "File cannot be read",
                footerDetail = "File cannot be read",
                isTruncated = false,
                truncationIndicators = emptyList(),
                unexpectedTrailingBytes = 0L,
                trailingDataNote = null,
                structuralErrors = listOf("File does not exist or permission was denied"),
                chunksOrBoxesSummary = emptyList(),
                recoveryClassification = RecoveryClassification.FAILED,
                fragmentationAssessment = FragmentationAssessment(
                    isSupportedOnSource = false,
                    statusLabel = "Source Unreadable",
                    contiguousLikelihood = "Unknown",
                    notes = "Cannot inspect extent or structure of unreadable file."
                )
            )
        }

        val size = file.length()
        if (size == 0L) {
            return FileStructureAnalysis(
                filePath = file.absolutePath,
                fileName = file.name,
                fileSize = 0L,
                recognizedSignatureHex = "",
                detectedFormat = "EMPTY",
                expectedStructureSummary = "Non-empty file payload",
                headerValid = false,
                footerValid = false,
                headerDetail = "0-byte empty file",
                footerDetail = "Missing footer",
                isTruncated = true,
                truncationIndicators = listOf("zero_byte_file"),
                unexpectedTrailingBytes = 0L,
                trailingDataNote = null,
                structuralErrors = listOf("File is 0 bytes (empty inode or truncated write)"),
                chunksOrBoxesSummary = emptyList(),
                recoveryClassification = RecoveryClassification.CORRUPTED,
                fragmentationAssessment = buildFragmentationAssessment(file)
            )
        }

        val headLen = min(64L, size).toInt()
        val head = ByteArray(headLen)
        val tailLen = min(4096L, size).toInt()
        val tail = ByteArray(tailLen)

        RandomAccessFile(file, "r").use { raf ->
            raf.seek(0L)
            raf.readFully(head)
            raf.seek(size - tailLen)
            raf.readFully(tail)
        }

        val sigHex = head.take(min(12, head.size)).joinToString(" ") {
            String.format(Locale.US, "%02X", it.toInt() and 0xFF)
        }

        // Dispatch format-specific structural parser
        return when {
            isJpegHeader(head) -> analyzeJpegStructure(file, size, sigHex, tail)
            isPngHeader(head) -> analyzePngStructure(file, size, sigHex)
            isWebpHeader(head) -> analyzeWebpStructure(file, size, sigHex, head)
            isPdfHeader(head) -> analyzePdfStructure(file, size, sigHex, head, tail)
            isZipHeader(head) -> analyzeZipStructure(file, size, sigHex, tail)
            isIsoBmffHeader(head) -> analyzeIsoBmffStructure(file, size, sigHex)
            isSqliteHeader(head) -> analyzeSqliteFileStructure(file, size, sigHex, head)
            else -> {
                FileStructureAnalysis(
                    filePath = file.absolutePath,
                    fileName = file.name,
                    fileSize = size,
                    recognizedSignatureHex = sigHex,
                    detectedFormat = "GENERIC / UNRECOGNIZED BINARY",
                    expectedStructureSummary = "No format-specific container specification matched",
                    headerValid = true,
                    footerValid = null,
                    headerDetail = "Raw byte stream begins with $sigHex",
                    footerDetail = "Format does not define a mandatory trailer marker",
                    isTruncated = false,
                    truncationIndicators = emptyList(),
                    unexpectedTrailingBytes = 0L,
                    trailingDataNote = null,
                    structuralErrors = emptyList(),
                    chunksOrBoxesSummary = listOf("Stream size: $size bytes"),
                    recoveryClassification = RecoveryClassification.UNVERIFIED,
                    fragmentationAssessment = buildFragmentationAssessment(file)
                )
            }
        }
    }

    private fun isJpegHeader(h: ByteArray): Boolean =
        h.size >= 3 && (h[0].toInt() and 0xFF) == 0xFF && (h[1].toInt() and 0xFF) == 0xD8 && (h[2].toInt() and 0xFF) == 0xFF

    private fun isPngHeader(h: ByteArray): Boolean =
        h.size >= 8 && (h[0].toInt() and 0xFF) == 0x89 && h[1] == 0x50.toByte() &&
            h[2] == 0x4E.toByte() && h[3] == 0x47.toByte() &&
            h[4] == 0x0D.toByte() && h[5] == 0x0A.toByte() &&
            h[6] == 0x1A.toByte() && h[7] == 0x0A.toByte()

    private fun isWebpHeader(h: ByteArray): Boolean =
        h.size >= 12 && h[0] == 'R'.code.toByte() && h[1] == 'I'.code.toByte() &&
            h[2] == 'F'.code.toByte() && h[3] == 'F'.code.toByte() &&
            h[8] == 'W'.code.toByte() && h[9] == 'E'.code.toByte() &&
            h[10] == 'B'.code.toByte() && h[11] == 'P'.code.toByte()

    private fun isPdfHeader(h: ByteArray): Boolean =
        h.size >= 5 && h[0] == '%'.code.toByte() && h[1] == 'P'.code.toByte() &&
            h[2] == 'D'.code.toByte() && h[3] == 'F'.code.toByte() && h[4] == '-'.code.toByte()

    private fun isZipHeader(h: ByteArray): Boolean =
        h.size >= 4 && h[0] == 'P'.code.toByte() && h[1] == 'K'.code.toByte() &&
            ((h[2] == 0x03.toByte() && h[3] == 0x04.toByte()) || (h[2] == 0x05.toByte() && h[3] == 0x06.toByte()))

    private fun isIsoBmffHeader(h: ByteArray): Boolean =
        h.size >= 8 && h[4] == 'f'.code.toByte() && h[5] == 't'.code.toByte() &&
            h[6] == 'y'.code.toByte() && h[7] == 'p'.code.toByte()

    private fun isSqliteHeader(h: ByteArray): Boolean =
        h.size >= 16 && String(h, 0, 15, StandardCharsets.US_ASCII) == "SQLite format 3"

    private fun analyzeJpegStructure(file: File, size: Long, sigHex: String, tail: ByteArray): FileStructureAnalysis {
        val markers = mutableListOf<String>()
        val errors = mutableListOf<String>()
        val truncations = mutableListOf<String>()
        var hasSof = false
        var hasSos = false

        // Walk top-level JPEG markers up to SOS (FF DA)
        runCatching {
            RandomAccessFile(file, "r").use { raf ->
                markers.add("SOI (0xFFD8) @ 0x0")
                var pos = 2L
                var safety = 0
                while (pos + 4 <= size && safety < 128) {
                    safety++
                    raf.seek(pos)
                    val b0 = raf.read()
                    if (b0 != 0xFF) break
                    var b1 = raf.read()
                    while (b1 == 0xFF) {
                        pos++
                        b1 = raf.read()
                    }
                    if (b1 < 0) break
                    if (b1 == 0xD9) {
                        markers.add("EOI (0xFFD9) @ 0x${pos.toString(16)}")
                        break
                    }
                    if (b1 in 0xC0..0xCF && b1 != 0xC4 && b1 != 0xC8 && b1 != 0xCC) {
                        hasSof = true
                        markers.add("SOF${b1 - 0xC0} (0xFF${b1.toString(16).uppercase(Locale.US)}) @ 0x${pos.toString(16)}")
                    } else if (b1 == 0xE1) {
                        markers.add("APP1/EXIF (0xFFE1) @ 0x${pos.toString(16)}")
                    } else if (b1 == 0xDB) {
                        markers.add("DQT (0xFFDB) @ 0x${pos.toString(16)}")
                    } else if (b1 == 0xC4) {
                        markers.add("DHT (0xFFC4) @ 0x${pos.toString(16)}")
                    }
                    if (b1 == 0xDA) {
                        hasSos = true
                        markers.add("SOS (0xFFDA) Entropy Scan @ 0x${pos.toString(16)}")
                        break
                    }
                    val lenHi = raf.read()
                    val lenLo = raf.read()
                    if (lenHi < 0 || lenLo < 0) break
                    val segLen = (lenHi shl 8) or lenLo
                    if (segLen < 2) {
                        errors.add("Invalid JPEG segment length ($segLen) at 0x${pos.toString(16)}")
                        break
                    }
                    pos += 2 + segLen
                }
            }
        }

        // Locate EOI (FF D9) in tail
        var eoiPosInTail = -1
        for (i in tail.size - 2 downTo 0) {
            if ((tail[i].toInt() and 0xFF) == 0xFF && (tail[i + 1].toInt() and 0xFF) == 0xD9) {
                eoiPosInTail = i
                break
            }
        }
        val footerValid = eoiPosInTail >= 0
        val trailingBytes = if (eoiPosInTail >= 0) (tail.size - (eoiPosInTail + 2)).toLong() else 0L
        if (!hasSof) errors.add("Missing Start of Frame (SOF) marker")
        if (!hasSos) {
            errors.add("Missing Start of Scan (SOS) marker")
            truncations.add("missing_jpeg_sos_entropy_stream")
        }
        if (!footerValid) {
            truncations.add("missing_jpeg_eoi_ffd9_marker")
            errors.add("Missing JPEG End of Image (0xFFD9) trailer marker")
        }

        val classification = when {
            footerValid && hasSos && hasSof -> RecoveryClassification.RECOVERED
            hasSos && hasSof && !footerValid -> RecoveryClassification.PARTIALLY_RECOVERED
            else -> RecoveryClassification.CORRUPTED
        }

        return FileStructureAnalysis(
            filePath = file.absolutePath,
            fileName = file.name,
            fileSize = size,
            recognizedSignatureHex = sigHex,
            detectedFormat = "JPEG",
            expectedStructureSummary = "SOI (FF D8) -> APPn/DQT/SOF/DHT segments -> SOS (FF DA) -> EOI (FF D9)",
            headerValid = true,
            footerValid = footerValid,
            headerDetail = "Valid JPEG SOI (FF D8 FF)",
            footerDetail = if (footerValid) "Valid JPEG EOI (FF D9) found" else "Missing JPEG EOI (FF D9) marker at end of stream",
            isTruncated = !footerValid || !hasSos,
            truncationIndicators = truncations,
            unexpectedTrailingBytes = trailingBytes,
            trailingDataNote = if (trailingBytes > 0) "$trailingBytes bytes present after JPEG EOI (FF D9) marker (e.g., Motion Photo payload or appended metadata)" else null,
            structuralErrors = errors,
            chunksOrBoxesSummary = markers,
            recoveryClassification = classification,
            fragmentationAssessment = buildFragmentationAssessment(file)
        )
    }

    private fun analyzePngStructure(file: File, size: Long, sigHex: String): FileStructureAnalysis {
        val chunks = mutableListOf<String>()
        val errors = mutableListOf<String>()
        val truncations = mutableListOf<String>()
        var hasIhdr = false
        var hasIdat = false
        var hasIend = false
        var iendEndOffset = -1L

        runCatching {
            RandomAccessFile(file, "r").use { raf ->
                var pos = 8L
                var chunkCount = 0
                while (pos + 12 <= size && chunkCount < 500) {
                    chunkCount++
                    raf.seek(pos)
                    val lenBytes = ByteArray(4)
                    val typeBytes = ByteArray(4)
                    raf.readFully(lenBytes)
                    raf.readFully(typeBytes)
                    val chunkLen = ByteBuffer.wrap(lenBytes).order(ByteOrder.BIG_ENDIAN).int.toLong() and 0xFFFFFFFFL
                    val type = String(typeBytes, StandardCharsets.US_ASCII)
                    val totalChunkSpan = 12L + chunkLen
                    if (pos + totalChunkSpan > size) {
                        truncations.add("png_chunk_${type}_truncated_at_0x${pos.toString(16)}")
                        errors.add("PNG chunk '$type' declares $chunkLen bytes at 0x${pos.toString(16)} but file ends early ($size bytes)")
                        break
                    }

                    // Verify CRC32 for critical small chunks (IHDR, IEND)
                    if (type == "IHDR" || type == "IEND") {
                        val crcCalc = CRC32()
                        crcCalc.update(typeBytes)
                        if (chunkLen in 1..1024) {
                            val dataBuf = ByteArray(chunkLen.toInt())
                            raf.readFully(dataBuf)
                            crcCalc.update(dataBuf)
                        } else if (chunkLen > 0) {
                            raf.seek(pos + 8 + chunkLen)
                        }
                        val crcBytes = ByteArray(4)
                        raf.readFully(crcBytes)
                        val storedCrc = ByteBuffer.wrap(crcBytes).order(ByteOrder.BIG_ENDIAN).int.toLong() and 0xFFFFFFFFL
                        if (crcCalc.value != storedCrc) {
                            errors.add("PNG chunk '$type' CRC32 mismatch (expected 0x${storedCrc.toString(16)}, computed 0x${crcCalc.value.toString(16)})")
                        }
                    }

                    chunks.add("$type ($chunkLen bytes) @ 0x${pos.toString(16)}")
                    if (type == "IHDR") hasIhdr = true
                    if (type == "IDAT") hasIdat = true
                    if (type == "IEND") {
                        hasIend = true
                        iendEndOffset = pos + totalChunkSpan
                        break
                    }
                    pos += totalChunkSpan
                }
            }
        }

        if (!hasIhdr) errors.add("Missing PNG IHDR header chunk")
        if (!hasIdat) {
            errors.add("Missing PNG IDAT image data chunk")
            truncations.add("missing_png_idat_chunk")
        }
        if (!hasIend) {
            errors.add("Missing PNG IEND trailer chunk")
            truncations.add("missing_png_iend_chunk")
        }
        val trailing = if (hasIend && iendEndOffset in 1..size) size - iendEndOffset else 0L

        val classification = when {
            hasIhdr && hasIdat && hasIend && errors.isEmpty() -> RecoveryClassification.RECOVERED
            hasIhdr && hasIdat && !hasIend -> RecoveryClassification.PARTIALLY_RECOVERED
            else -> RecoveryClassification.CORRUPTED
        }

        return FileStructureAnalysis(
            filePath = file.absolutePath,
            fileName = file.name,
            fileSize = size,
            recognizedSignatureHex = sigHex,
            detectedFormat = "PNG",
            expectedStructureSummary = "8-Byte Signature -> IHDR -> IDAT chunk(s) -> IEND + CRC32",
            headerValid = hasIhdr,
            footerValid = hasIend,
            headerDetail = if (hasIhdr) "Valid PNG Signature & IHDR chunk" else "PNG Signature present, IHDR invalid",
            footerDetail = if (hasIend) "Valid PNG IEND chunk verified" else "Missing PNG IEND chunk",
            isTruncated = !hasIend || truncations.isNotEmpty(),
            truncationIndicators = truncations,
            unexpectedTrailingBytes = trailing,
            trailingDataNote = if (trailing > 0) "$trailing trailing bytes after PNG IEND chunk" else null,
            structuralErrors = errors,
            chunksOrBoxesSummary = chunks,
            recoveryClassification = classification,
            fragmentationAssessment = buildFragmentationAssessment(file)
        )
    }

    private fun analyzeWebpStructure(file: File, size: Long, sigHex: String, head: ByteArray): FileStructureAnalysis {
        val riffPayloadSize = if (head.size >= 8) {
            ByteBuffer.wrap(head, 4, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
        } else 0L
        val expectedTotal = riffPayloadSize + 8L
        val fourCc = if (head.size >= 16) String(head, 12, 4, StandardCharsets.US_ASCII) else "UNKNOWN"
        val isTruncated = size < expectedTotal
        val trailing = if (size > expectedTotal && expectedTotal > 8L) size - expectedTotal else 0L
        val errors = mutableListOf<String>()
        val truncs = mutableListOf<String>()
        if (isTruncated) {
            truncs.add("webp_riff_truncated_expected_${expectedTotal}_actual_$size")
            errors.add("RIFF header declares $expectedTotal total bytes, but file is truncated at $size bytes")
        }

        val classification = when {
            !isTruncated && fourCc.startsWith("VP8") -> RecoveryClassification.RECOVERED
            isTruncated && size > 32L -> RecoveryClassification.PARTIALLY_RECOVERED
            else -> RecoveryClassification.CORRUPTED
        }

        return FileStructureAnalysis(
            filePath = file.absolutePath,
            fileName = file.name,
            fileSize = size,
            recognizedSignatureHex = sigHex,
            detectedFormat = "WEBP",
            expectedStructureSummary = "RIFF + 32-bit LE size + WEBP + VP8/VP8L/VP8X chunks",
            headerValid = true,
            footerValid = !isTruncated,
            headerDetail = "RIFF WebP ($fourCc), declared size $expectedTotal bytes",
            footerDetail = if (!isTruncated) "Complete RIFF payload ($size bytes)" else "Truncated before declared RIFF boundary ($size / $expectedTotal bytes)",
            isTruncated = isTruncated,
            truncationIndicators = truncs,
            unexpectedTrailingBytes = trailing,
            trailingDataNote = if (trailing > 0) "$trailing bytes present beyond declared RIFF container size" else null,
            structuralErrors = errors,
            chunksOrBoxesSummary = listOf("RIFF WEBP header", "Primary chunk: $fourCc", "Declared payload: $riffPayloadSize bytes"),
            recoveryClassification = classification,
            fragmentationAssessment = buildFragmentationAssessment(file)
        )
    }

    private fun analyzePdfStructure(file: File, size: Long, sigHex: String, head: ByteArray, tail: ByteArray): FileStructureAnalysis {
        val headerStr = String(head, 0, min(head.size, 16), StandardCharsets.ISO_8859_1).lineSequence().firstOrNull() ?: "%PDF"
        val tailStr = String(tail, StandardCharsets.ISO_8859_1)
        val eofIdx = tailStr.lastIndexOf("%%EOF")
        val hasEof = eofIdx >= 0
        val hasStartXref = tailStr.contains("startxref")
        val trailingBytes = if (hasEof) {
            val after = tailStr.substring(eofIdx + 5).trim('\r', '\n', ' ')
            after.toByteArray(StandardCharsets.ISO_8859_1).size.toLong()
        } else 0L

        val errors = mutableListOf<String>()
        val truncs = mutableListOf<String>()
        if (!hasEof) {
            truncs.add("missing_pdf_eof_marker")
            errors.add("Missing PDF %%EOF trailer marker")
        }
        if (!hasStartXref) {
            errors.add("Missing PDF startxref table pointer near end of file")
        }

        val classification = when {
            hasEof && hasStartXref -> RecoveryClassification.RECOVERED
            hasEof || size > 256L -> RecoveryClassification.PARTIALLY_RECOVERED
            else -> RecoveryClassification.CORRUPTED
        }

        return FileStructureAnalysis(
            filePath = file.absolutePath,
            fileName = file.name,
            fileSize = size,
            recognizedSignatureHex = sigHex,
            detectedFormat = "PDF",
            expectedStructureSummary = "%PDF-1.x Header -> Indirect Objects -> xref/XRef Stream -> startxref -> %%EOF",
            headerValid = true,
            footerValid = hasEof,
            headerDetail = "PDF Header: $headerStr",
            footerDetail = if (hasEof) "Valid %%EOF trailer found" else "Missing %%EOF trailer marker",
            isTruncated = !hasEof,
            truncationIndicators = truncs,
            unexpectedTrailingBytes = trailingBytes,
            trailingDataNote = if (trailingBytes > 0) "$trailingBytes non-whitespace bytes after final %%EOF marker" else null,
            structuralErrors = errors,
            chunksOrBoxesSummary = listOf(
                "Header: $headerStr",
                "startxref present: $hasStartXref",
                "%%EOF trailer present: $hasEof"
            ),
            recoveryClassification = classification,
            fragmentationAssessment = buildFragmentationAssessment(file)
        )
    }

    private fun analyzeZipStructure(file: File, size: Long, sigHex: String, tail: ByteArray): FileStructureAnalysis {
        // Locate End of Central Directory (PK\x05\x06) in tail
        var eocdPos = -1
        for (i in tail.size - 22 downTo 0) {
            if (tail[i] == 'P'.code.toByte() && tail[i + 1] == 'K'.code.toByte() &&
                tail[i + 2] == 0x05.toByte() && tail[i + 3] == 0x06.toByte()
            ) {
                eocdPos = i
                break
            }
        }
        val hasEocd = eocdPos >= 0
        var trailingBytes = 0L
        var declaredEntries = 0
        if (hasEocd && eocdPos + 22 <= tail.size) {
            declaredEntries = ByteBuffer.wrap(tail, eocdPos + 10, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
            val commentLen = ByteBuffer.wrap(tail, eocdPos + 20, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
            val expectedEnd = eocdPos + 22 + commentLen
            if (tail.size > expectedEnd) {
                trailingBytes = (tail.size - expectedEnd).toLong()
            }
        }

        val errors = mutableListOf<String>()
        val truncs = mutableListOf<String>()
        if (!hasEocd) {
            truncs.add("missing_zip_eocd_central_directory")
            errors.add("Missing ZIP End of Central Directory (PK 05 06) record")
        }

        val classification = when {
            hasEocd -> RecoveryClassification.RECOVERED
            size > 30L -> RecoveryClassification.PARTIALLY_RECOVERED
            else -> RecoveryClassification.CORRUPTED
        }

        return FileStructureAnalysis(
            filePath = file.absolutePath,
            fileName = file.name,
            fileSize = size,
            recognizedSignatureHex = sigHex,
            detectedFormat = "ZIP / OOXML / APK",
            expectedStructureSummary = "Local File Headers (PK 03 04) -> Central Directory (PK 01 02) -> EOCD (PK 05 06)",
            headerValid = true,
            footerValid = hasEocd,
            headerDetail = "Valid ZIP Local Header (PK 03 04)",
            footerDetail = if (hasEocd) "Valid EOCD (PK 05 06) with $declaredEntries central directory records" else "Missing EOCD (PK 05 06)",
            isTruncated = !hasEocd,
            truncationIndicators = truncs,
            unexpectedTrailingBytes = trailingBytes,
            trailingDataNote = if (trailingBytes > 0) "$trailingBytes bytes found after ZIP EOCD comment boundary" else null,
            structuralErrors = errors,
            chunksOrBoxesSummary = listOf(
                "Local Header: PK 03 04",
                "Central Directory EOCD present: $hasEocd",
                "Declared Central Directory entries: $declaredEntries"
            ),
            recoveryClassification = classification,
            fragmentationAssessment = buildFragmentationAssessment(file)
        )
    }

    private fun analyzeIsoBmffStructure(file: File, size: Long, sigHex: String): FileStructureAnalysis {
        val boxes = mutableListOf<String>()
        val errors = mutableListOf<String>()
        val truncs = mutableListOf<String>()
        var hasFtyp = false
        var hasMoov = false
        var hasMdat = false

        runCatching {
            RandomAccessFile(file, "r").use { raf ->
                var pos = 0L
                var count = 0
                while (pos + 8 <= size && count < 64) {
                    count++
                    raf.seek(pos)
                    val header = ByteArray(8)
                    raf.readFully(header)
                    var boxSize = ByteBuffer.wrap(header, 0, 4).order(ByteOrder.BIG_ENDIAN).int.toLong() and 0xFFFFFFFFL
                    val type = String(header, 4, 4, StandardCharsets.US_ASCII)
                    if (boxSize == 1L && pos + 16 <= size) {
                        val ext = ByteArray(8)
                        raf.readFully(ext)
                        boxSize = ByteBuffer.wrap(ext).order(ByteOrder.BIG_ENDIAN).long
                    } else if (boxSize == 0L) {
                        boxSize = size - pos
                    }
                    if (boxSize < 8L) {
                        errors.add("Invalid ISOBMFF atom size ($boxSize) at 0x${pos.toString(16)}")
                        break
                    }
                    boxes.add("$type ($boxSize bytes) @ 0x${pos.toString(16)}")
                    if (type == "ftyp") hasFtyp = true
                    if (type == "moov") hasMoov = true
                    if (type == "mdat") hasMdat = true
                    if (pos + boxSize > size) {
                        truncs.add("isobmff_box_${type}_truncated")
                        errors.add("ISOBMFF box '$type' extends past EOF (${pos + boxSize} > $size)")
                        break
                    }
                    pos += boxSize
                }
            }
        }

        if (!hasMoov) {
            errors.add("Missing 'moov' movie metadata atom (common in unfinalized video recordings)")
            truncs.add("missing_isobmff_moov_atom")
        }
        if (!hasMdat) {
            errors.add("Missing 'mdat' media payload atom")
        }

        val classification = when {
            hasFtyp && hasMoov && hasMdat && truncs.isEmpty() -> RecoveryClassification.RECOVERED
            hasFtyp && (hasMdat || hasMoov) -> RecoveryClassification.PARTIALLY_RECOVERED
            else -> RecoveryClassification.CORRUPTED
        }

        return FileStructureAnalysis(
            filePath = file.absolutePath,
            fileName = file.name,
            fileSize = size,
            recognizedSignatureHex = sigHex,
            detectedFormat = "MP4 / MOV / ISOBMFF",
            expectedStructureSummary = "ftyp atom -> moov (movie header/tracks) -> mdat (media samples)",
            headerValid = hasFtyp,
            footerValid = hasMoov && truncs.isEmpty(),
            headerDetail = if (hasFtyp) "Valid ISOBMFF ftyp header" else "Missing ftyp box",
            footerDetail = if (hasMoov && truncs.isEmpty()) "Both moov and mdat atoms verified within file bounds" else "Incomplete box tree (moov=$hasMoov, mdat=$hasMdat)",
            isTruncated = truncs.isNotEmpty() || !hasMoov,
            truncationIndicators = truncs,
            unexpectedTrailingBytes = 0L,
            trailingDataNote = null,
            structuralErrors = errors,
            chunksOrBoxesSummary = boxes,
            recoveryClassification = classification,
            fragmentationAssessment = buildFragmentationAssessment(file)
        )
    }

    private fun analyzeSqliteFileStructure(file: File, size: Long, sigHex: String, head: ByteArray): FileStructureAnalysis {
        val pageSizeRaw = if (head.size >= 18) ByteBuffer.wrap(head, 16, 2).order(ByteOrder.BIG_ENDIAN).short.toInt() and 0xFFFF else 0
        val pageSize = if (pageSizeRaw == 1) 65536 else pageSizeRaw
        val totalPages = if (head.size >= 32) ByteBuffer.wrap(head, 28, 4).order(ByteOrder.BIG_ENDIAN).int.toLong() and 0xFFFFFFFFL else 0L
        val expectedBytes = if (pageSize > 0 && totalPages > 0) pageSize.toLong() * totalPages else size
        val isTruncated = expectedBytes > size && totalPages > 0
        val errors = mutableListOf<String>()
        val truncs = mutableListOf<String>()
        if (isTruncated) {
            truncs.add("sqlite_pages_truncated")
            errors.add("SQLite header declares $totalPages pages ($expectedBytes bytes), actual size is $size bytes")
        }

        return FileStructureAnalysis(
            filePath = file.absolutePath,
            fileName = file.name,
            fileSize = size,
            recognizedSignatureHex = sigHex,
            detectedFormat = "SQLITE 3 DATABASE",
            expectedStructureSummary = "100-Byte SQLite 3 Header + Fixed-Size B-Tree Pages ($pageSize bytes/page)",
            headerValid = pageSize >= 512,
            footerValid = !isTruncated,
            headerDetail = "SQLite 3 header valid (Page size: $pageSize bytes, Declared pages: $totalPages)",
            footerDetail = if (!isTruncated) "Page count aligns with file size" else "Truncated before declared page count",
            isTruncated = isTruncated,
            truncationIndicators = truncs,
            unexpectedTrailingBytes = 0L,
            trailingDataNote = null,
            structuralErrors = errors,
            chunksOrBoxesSummary = listOf("Page size: $pageSize bytes", "Declared pages: $totalPages"),
            recoveryClassification = if (!isTruncated) RecoveryClassification.RECOVERED else RecoveryClassification.PARTIALLY_RECOVERED,
            fragmentationAssessment = buildFragmentationAssessment(file)
        )
    }

    private fun buildFragmentationAssessment(file: File): FragmentationAssessment {
        return FragmentationAssessment(
            isSupportedOnSource = false,
            statusLabel = "VFS File-Level Stream (Block Extents Abstracted by Kernel)",
            contiguousLikelihood = "Logical stream is contiguous via VFS; physical flash block extents (fiemap) require privileged ioctl access",
            notes = "Android user-space accesses files through the VFS/FUSE/sdcardfs layer. Non-contiguous physical flash blocks cannot be reassembled without filesystem extent metadata."
        )
    }

    // =========================================================================
    // 3. SIGNATURE-BASED STREAM CARVING ENGINE (Section 4)
    // =========================================================================

    /**
     * Carves embedded JPEG, PNG, WebP, PDF, and ZIP streams from an accessible container,
     * cache blob, `.thumbdata`, or user-supplied raw disk image in bounded memory.
     */
    suspend fun carveStreamsFromAccessibleSource(
        sourceFile: File,
        outputDir: File,
        maxCarvedOutputs: Int = 25,
        maxSingleCarveBytes: Long = 16L * 1024L * 1024L
    ): List<CarvedStreamResult> = withContext(Dispatchers.IO) {
        if (!sourceFile.exists() || !sourceFile.isFile || !sourceFile.canRead()) {
            return@withContext emptyList()
        }
        outputDir.mkdirs()
        val fileLen = sourceFile.length()
        if (fileLen < 16L) return@withContext emptyList()

        val results = mutableListOf<CarvedStreamResult>()
        val scanBuf = ByteArray(STREAM_CHUNK + 16)
        var pos = 0L

        RandomAccessFile(sourceFile, "r").use { raf ->
            while (pos < fileLen && results.size < maxCarvedOutputs) {
                currentCoroutineContext().ensureActive()
                raf.seek(pos)
                val toRead = min(scanBuf.size.toLong(), fileLen - pos).toInt()
                if (toRead < 8) break
                val read = raf.read(scanBuf, 0, toRead)
                if (read < 8) break

                var i = 0
                val limit = read - 8
                while (i <= limit && results.size < maxCarvedOutputs) {
                    val absOffset = pos + i
                    val b0 = scanBuf[i].toInt() and 0xFF
                    val b1 = scanBuf[i + 1].toInt() and 0xFF
                    val b2 = scanBuf[i + 2].toInt() and 0xFF
                    val b3 = scanBuf[i + 3].toInt() and 0xFF

                    // 1. Check JPEG SOI: FF D8 FF E0/E1/DB
                    if (b0 == 0xFF && b1 == 0xD8 && b2 == 0xFF && (b3 == 0xE0 || b3 == 0xE1 || b3 == 0xDB || b3 == 0xFE)) {
                        val carved = carveSingleJpeg(raf, absOffset, fileLen, outputDir, results.size + 1, maxSingleCarveBytes)
                        if (carved != null) {
                            results.add(carved)
                            val jump = (carved.endOffsetExclusive - pos).toInt()
                            if (jump > i) {
                                i = jump
                                continue
                            }
                        }
                    }
                    // 2. Check PNG: 89 50 4E 47 0D 0A 1A 0A
                    else if (b0 == 0x89 && b1 == 0x50 && b2 == 0x4E && b3 == 0x47 &&
                        (scanBuf[i + 4].toInt() and 0xFF) == 0x0D && (scanBuf[i + 5].toInt() and 0xFF) == 0x0A
                    ) {
                        val carved = carveSinglePng(raf, absOffset, fileLen, outputDir, results.size + 1, maxSingleCarveBytes)
                        if (carved != null) {
                            results.add(carved)
                            val jump = (carved.endOffsetExclusive - pos).toInt()
                            if (jump > i) {
                                i = jump
                                continue
                            }
                        }
                    }
                    // 3. Check PDF: %PDF-
                    else if (b0 == 0x25 && b1 == 0x50 && b2 == 0x44 && b3 == 0x46 && (scanBuf[i + 4].toInt() and 0xFF) == 0x2D) {
                        val carved = carveSinglePdf(raf, absOffset, fileLen, outputDir, results.size + 1, maxSingleCarveBytes)
                        if (carved != null) {
                            results.add(carved)
                            val jump = (carved.endOffsetExclusive - pos).toInt()
                            if (jump > i) {
                                i = jump
                                continue
                            }
                        }
                    }
                    i++
                }
                pos += STREAM_CHUNK
            }
        }
        results
    }

    private fun carveSingleJpeg(
        raf: RandomAccessFile,
        startOffset: Long,
        fileLen: Long,
        outputDir: File,
        index: Int,
        maxBytes: Long
    ): CarvedStreamResult? {
        val searchLimit = min(fileLen, startOffset + maxBytes)
        var cursor = startOffset + 2L
        var foundEoiEnd = -1L
        val buf = ByteArray(16 * 1024)

        while (cursor < searchLimit) {
            raf.seek(cursor)
            val n = raf.read(buf, 0, min(buf.size.toLong(), searchLimit - cursor).toInt())
            if (n < 2) break
            for (k in 0 until n - 1) {
                if ((buf[k].toInt() and 0xFF) == 0xFF && (buf[k + 1].toInt() and 0xFF) == 0xD9) {
                    foundEoiEnd = cursor + k + 2L
                    break
                }
            }
            if (foundEoiEnd > 0) break
            cursor += n - 1
        }

        val endExclusive = if (foundEoiEnd > 0) foundEoiEnd else min(searchLimit, startOffset + 256 * 1024L)
        val len = endExclusive - startOffset
        if (len < 32L) return null

        val outFile = File(outputDir, String.format(Locale.US, "carved_%03d_0x%08X.jpg", index, startOffset))
        copyRangeToFile(raf, startOffset, len, outFile)
        val struct = analyzeFileStructure(outFile)
        val sha = ForensicAnalyzer.computeSha256Sync(outFile)

        return CarvedStreamResult(
            index = index,
            format = "JPEG",
            extension = "jpg",
            startOffset = startOffset,
            endOffsetExclusive = endExclusive,
            lengthBytes = len,
            outputFile = outFile,
            sha256 = sha,
            classification = struct.recoveryClassification,
            validationSummary = struct.footerDetail,
            fragmentationNote = "Carved contiguously from byte stream [0x${startOffset.toString(16)}..0x${endExclusive.toString(16)}]"
        )
    }

    private fun carveSinglePng(
        raf: RandomAccessFile,
        startOffset: Long,
        fileLen: Long,
        outputDir: File,
        index: Int,
        maxBytes: Long
    ): CarvedStreamResult? {
        val searchLimit = min(fileLen, startOffset + maxBytes)
        var cursor = startOffset + 8L
        var foundIendEnd = -1L
        val buf = ByteArray(16 * 1024)

        while (cursor < searchLimit) {
            raf.seek(cursor)
            val n = raf.read(buf, 0, min(buf.size.toLong(), searchLimit - cursor).toInt())
            if (n < 8) break
            for (k in 0 until n - 7) {
                if (buf[k] == 'I'.code.toByte() && buf[k + 1] == 'E'.code.toByte() &&
                    buf[k + 2] == 'N'.code.toByte() && buf[k + 3] == 'D'.code.toByte()
                ) {
                    foundIendEnd = cursor + k + 8L // 4 bytes "IEND" + 4 bytes CRC32
                    break
                }
            }
            if (foundIendEnd > 0) break
            cursor += n - 7
        }

        val endExclusive = if (foundIendEnd > 0 && foundIendEnd <= searchLimit) foundIendEnd else min(searchLimit, startOffset + 128 * 1024L)
        val len = endExclusive - startOffset
        if (len < 64L) return null

        val outFile = File(outputDir, String.format(Locale.US, "carved_%03d_0x%08X.png", index, startOffset))
        copyRangeToFile(raf, startOffset, len, outFile)
        val struct = analyzeFileStructure(outFile)
        val sha = ForensicAnalyzer.computeSha256Sync(outFile)

        return CarvedStreamResult(
            index = index,
            format = "PNG",
            extension = "png",
            startOffset = startOffset,
            endOffsetExclusive = endExclusive,
            lengthBytes = len,
            outputFile = outFile,
            sha256 = sha,
            classification = struct.recoveryClassification,
            validationSummary = struct.footerDetail,
            fragmentationNote = "Carved contiguously from byte stream [0x${startOffset.toString(16)}..0x${endExclusive.toString(16)}]"
        )
    }

    private fun carveSinglePdf(
        raf: RandomAccessFile,
        startOffset: Long,
        fileLen: Long,
        outputDir: File,
        index: Int,
        maxBytes: Long
    ): CarvedStreamResult? {
        val searchLimit = min(fileLen, startOffset + maxBytes)
        var cursor = startOffset + 5L
        var foundEofEnd = -1L
        val buf = ByteArray(16 * 1024)

        while (cursor < searchLimit) {
            raf.seek(cursor)
            val n = raf.read(buf, 0, min(buf.size.toLong(), searchLimit - cursor).toInt())
            if (n < 5) break
            for (k in 0 until n - 4) {
                if (buf[k] == '%'.code.toByte() && buf[k + 1] == '%'.code.toByte() &&
                    buf[k + 2] == 'E'.code.toByte() && buf[k + 3] == 'O'.code.toByte() && buf[k + 4] == 'F'.code.toByte()
                ) {
                    foundEofEnd = cursor + k + 5L
                    break
                }
            }
            if (foundEofEnd > 0) break
            cursor += n - 4
        }

        val endExclusive = if (foundEofEnd > 0) min(searchLimit, foundEofEnd + 2L) else min(searchLimit, startOffset + 128 * 1024L)
        val len = endExclusive - startOffset
        if (len < 64L) return null

        val outFile = File(outputDir, String.format(Locale.US, "carved_%03d_0x%08X.pdf", index, startOffset))
        copyRangeToFile(raf, startOffset, len, outFile)
        val struct = analyzeFileStructure(outFile)
        val sha = ForensicAnalyzer.computeSha256Sync(outFile)

        return CarvedStreamResult(
            index = index,
            format = "PDF",
            extension = "pdf",
            startOffset = startOffset,
            endOffsetExclusive = endExclusive,
            lengthBytes = len,
            outputFile = outFile,
            sha256 = sha,
            classification = struct.recoveryClassification,
            validationSummary = struct.footerDetail,
            fragmentationNote = "Carved contiguously from byte stream [0x${startOffset.toString(16)}..0x${endExclusive.toString(16)}]"
        )
    }

    private fun copyRangeToFile(raf: RandomAccessFile, start: Long, length: Long, dest: File) {
        raf.seek(start)
        var remaining = length
        val buf = ByteArray(STREAM_CHUNK)
        FileOutputStream(dest).use { fos ->
            while (remaining > 0) {
                val n = raf.read(buf, 0, min(buf.size.toLong(), remaining).toInt())
                if (n <= 0) break
                fos.write(buf, 0, n)
                remaining -= n
            }
        }
    }

    // =========================================================================
    // 4. ARCHIVE FORENSICS ENGINE (Section 5.G)
    // =========================================================================

    suspend fun inspectArchiveForensics(
        archiveFile: File,
        maxEntries: Int = 250
    ): ArchiveForensicReport = withContext(Dispatchers.IO) {
        if (!archiveFile.exists() || !archiveFile.isFile || !archiveFile.canRead()) {
            return@withContext ArchiveForensicReport(
                archivePath = archiveFile.absolutePath,
                archiveName = archiveFile.name,
                fileSize = 0L,
                sha256 = "unavailable",
                structureValid = false,
                hasEndOfCentralDirectory = false,
                isTruncatedOrCorrupted = true,
                totalEntries = 0,
                entries = emptyList(),
                structuralAnomalies = listOf("Archive file does not exist or is not readable")
            )
        }

        val sha256 = ForensicAnalyzer.computeSha256Sync(archiveFile)
        val struct = analyzeFileStructure(archiveFile)
        val hasEocd = struct.footerValid == true
        val anomalies = mutableListOf<String>()
        anomalies.addAll(struct.structuralErrors)

        val entries = mutableListOf<ArchiveForensicEntry>()
        var streamError: String? = null

        runCatching {
            ZipInputStream(BufferedInputStream(FileInputStream(archiveFile))).use { zis ->
                var idx = 0
                var ze: ZipEntry? = zis.nextEntry
                val buf = ByteArray(16 * 1024)
                while (ze != null && idx < maxEntries) {
                    currentCoroutineContext().ensureActive()
                    idx++
                    val name = ze.name ?: ""
                    val hasTraversal = name.contains("../") || name.contains("..\\") || name.startsWith("/")
                    if (hasTraversal) {
                        anomalies.add("Entry #$idx ('$name') contains relative path traversal ('..') or absolute leading slash")
                    }

                    // Compute SHA-256 of entry stream without writing to disk
                    val digest = MessageDigest.getInstance("SHA-256")
                    var actualReadBytes = 0L
                    var n = zis.read(buf)
                    while (n != -1) {
                        if (n > 0) {
                            digest.update(buf, 0, n)
                            actualReadBytes += n
                            if (actualReadBytes > 128L * 1024L * 1024L) {
                                anomalies.add("Entry #$idx ('$name') exceeds 128 MB stream inspection cap; stream hashing bounded")
                                break
                            }
                        }
                        n = zis.read(buf)
                    }
                    val entrySha = if (!ze.isDirectory) {
                        digest.digest().joinToString("") { String.format(Locale.US, "%02x", it.toInt() and 0xFF) }
                    } else null

                    val compSize = if (ze.compressedSize >= 0) ze.compressedSize else 0L
                    val uncompSize = if (ze.size >= 0) ze.size else actualReadBytes
                    val ratio = if (compSize > 0) uncompSize.toDouble() / compSize.toDouble() else 1.0
                    val highRatio = ratio > 100.0 && uncompSize > 10 * 1024 * 1024L
                    if (highRatio) {
                        anomalies.add("Entry #$idx ('$name') exhibits high compression ratio (${String.format(Locale.US, "%.1fx", ratio)})")
                    }

                    val crcHex = if (ze.crc >= 0) String.format(Locale.US, "0x%08X", ze.crc) else "unknown"
                    val methodStr = when (ze.method) {
                        ZipEntry.STORED -> "STORED (0)"
                        ZipEntry.DEFLATED -> "DEFLATED (8)"
                        else -> "METHOD_${ze.method}"
                    }

                    entries.add(
                        ArchiveForensicEntry(
                            index = idx,
                            entryName = name,
                            isDirectory = ze.isDirectory,
                            compressedSize = compSize,
                            uncompressedSize = uncompSize,
                            compressionMethod = methodStr,
                            compressionRatio = ratio,
                            crc32Hex = crcHex,
                            sha256 = entrySha,
                            lastModifiedIso = if (ze.time > 0) ForensicTimeUtil.epochMillisToIsoUtc(ze.time) else null,
                            hasPathTraversalAnomaly = hasTraversal,
                            hasHighCompressionRatioAnomaly = highRatio
                        )
                    )
                    zis.closeEntry()
                    ze = zis.nextEntry
                }
            }
        }.onFailure { e ->
            if (e is CancellationException) throw e
            streamError = "Archive stream parsing error: ${e.javaClass.simpleName}: ${e.message}"
            anomalies.add(streamError!!)
        }

        val isCorrupted = !hasEocd || streamError != null

        ArchiveForensicReport(
            archivePath = archiveFile.absolutePath,
            archiveName = archiveFile.name,
            fileSize = archiveFile.length(),
            sha256 = sha256,
            structureValid = hasEocd && streamError == null,
            hasEndOfCentralDirectory = hasEocd,
            isTruncatedOrCorrupted = isCorrupted,
            totalEntries = entries.size,
            entries = entries,
            structuralAnomalies = anomalies.distinct()
        )
    }

    // =========================================================================
    // 5. SQLITE FORENSICS ENGINE (Section 5.H)
    // =========================================================================

    suspend fun inspectSqliteDatabase(dbFile: File): SqliteForensicReport = withContext(Dispatchers.IO) {
        if (!dbFile.exists() || !dbFile.isFile || !dbFile.canRead()) {
            return@withContext SqliteForensicReport(
                dbPath = dbFile.absolutePath,
                dbName = dbFile.name,
                fileSize = 0L,
                sha256 = "unavailable",
                isValidSqliteHeader = false,
                sqliteVersionString = "Unavailable",
                pageSizeBytes = 0,
                totalPagesInHeader = 0L,
                textEncoding = "Unavailable",
                freelistTrunkPage = 0L,
                freelistPageCount = 0L,
                fileChangeCounter = 0L,
                integrityCheckResult = "File inaccessible",
                walFilePresent = false,
                walFileSizeBytes = 0L,
                journalFilePresent = false,
                journalFileSizeBytes = 0L,
                tables = emptyList(),
                indexes = emptyList(),
                unallocatedRemnants = emptyList(),
                limitations = listOf("Target SQLite database file does not exist or cannot be read.")
            )
        }

        val size = dbFile.length()
        val sha256 = ForensicAnalyzer.computeSha256Sync(dbFile)
        val header = ByteArray(min(100L, size).toInt())
        FileInputStream(dbFile).use { it.read(header) }

        val isValidHeader = header.size >= 16 && String(header, 0, 15, StandardCharsets.US_ASCII) == "SQLite format 3"
        if (!isValidHeader) {
            return@withContext SqliteForensicReport(
                dbPath = dbFile.absolutePath,
                dbName = dbFile.name,
                fileSize = size,
                sha256 = sha256,
                isValidSqliteHeader = false,
                sqliteVersionString = "Not a valid SQLite 3 header",
                pageSizeBytes = 0,
                totalPagesInHeader = 0L,
                textEncoding = "Unknown",
                freelistTrunkPage = 0L,
                freelistPageCount = 0L,
                fileChangeCounter = 0L,
                integrityCheckResult = "failed_invalid_sqlite_header",
                walFilePresent = false,
                walFileSizeBytes = 0L,
                journalFilePresent = false,
                journalFileSizeBytes = 0L,
                tables = emptyList(),
                indexes = emptyList(),
                unallocatedRemnants = emptyList(),
                limitations = listOf("File does not start with the standard 16-byte 'SQLite format 3\\0' signature (may be SQLCipher encrypted or another format).")
            )
        }

        val bb = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN)
        val rawPageSize = bb.getShort(16).toInt() and 0xFFFF
        val pageSize = if (rawPageSize == 1) 65536 else rawPageSize
        val changeCounter = bb.getInt(24).toLong() and 0xFFFFFFFFL
        val totalPages = bb.getInt(28).toLong() and 0xFFFFFFFFL
        val freelistTrunk = bb.getInt(32).toLong() and 0xFFFFFFFFL
        val freelistCount = bb.getInt(36).toLong() and 0xFFFFFFFFL
        val encodingCode = bb.getInt(56)
        val textEncoding = when (encodingCode) {
            1 -> "UTF-8 (1)"
            2 -> "UTF-16le (2)"
            3 -> "UTF-16be (3)"
            else -> "Code $encodingCode"
        }
        val sqliteVerNum = bb.getInt(96)
        val sqliteVerStr = if (sqliteVerNum > 0) {
            val maj = sqliteVerNum / 1000000
            val minV = (sqliteVerNum / 1000) % 1000
            val rel = sqliteVerNum % 1000
            "$maj.$minV.$rel ($sqliteVerNum)"
        } else "Unknown"

        val walFile = File(dbFile.absolutePath + "-wal")
        val journalFile = File(dbFile.absolutePath + "-journal")

        var integrityResult = "not_tested"
        val tables = mutableListOf<SqliteTableSchema>()
        val indexes = mutableListOf<String>()
        val limitations = mutableListOf<String>()

        // Open read-only using Android SQLiteDatabase to inspect schema, integrity, and sample rows
        runCatching {
            val db = SQLiteDatabase.openDatabase(dbFile.absolutePath, null, SQLiteDatabase.OPEN_READONLY or SQLiteDatabase.NO_LOCALIZED_COLLATORS)
            db.use { sqlite ->
                // 1. PRAGMA integrity_check
                runCatching {
                    sqlite.rawQuery("PRAGMA integrity_check(5)", null).use { c ->
                        val msgs = mutableListOf<String>()
                        while (c.moveToNext()) {
                            msgs.add(c.getString(0) ?: "")
                        }
                        integrityResult = msgs.joinToString("; ").ifBlank { "ok" }
                    }
                }.onFailure {
                    integrityResult = "error: ${it.message}"
                }

                // 2. Query sqlite_master
                sqlite.rawQuery("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name", null).use { c ->
                    while (c.moveToNext()) {
                        val type = c.getString(0) ?: ""
                        val name = c.getString(1) ?: ""
                        val sql = c.getString(3) ?: ""
                        if (type == "index") {
                            indexes.add("$name ${if (sql.isNotBlank()) "($sql)" else "(autoindex)"}")
                        } else if (type == "table" || type == "view") {
                            var rowCount = 0L
                            val samples = mutableListOf<Map<String, String>>()
                            val safeName = name.replace("\"", "\"\"")
                            runCatching {
                                sqlite.rawQuery("SELECT COUNT(*) FROM \"$safeName\"", null).use { cntCursor ->
                                    if (cntCursor.moveToFirst()) rowCount = cntCursor.getLong(0)
                                }
                                sqlite.rawQuery("SELECT * FROM \"$safeName\" LIMIT 5", null).use { rowCursor ->
                                    val colNames = rowCursor.columnNames
                                    while (rowCursor.moveToNext()) {
                                        val rowMap = linkedMapOf<String, String>()
                                        for (colIdx in colNames.indices) {
                                            val colVal = when (rowCursor.getType(colIdx)) {
                                                android.database.Cursor.FIELD_TYPE_NULL -> "NULL"
                                                android.database.Cursor.FIELD_TYPE_INTEGER -> rowCursor.getLong(colIdx).toString()
                                                android.database.Cursor.FIELD_TYPE_FLOAT -> rowCursor.getDouble(colIdx).toString()
                                                android.database.Cursor.FIELD_TYPE_BLOB -> "<BLOB ${rowCursor.getBlob(colIdx)?.size ?: 0} bytes>"
                                                else -> rowCursor.getString(colIdx) ?: ""
                                            }
                                            rowMap[colNames[colIdx]] = colVal
                                        }
                                        samples.add(rowMap)
                                    }
                                }
                            }
                            tables.add(
                                SqliteTableSchema(
                                    name = name,
                                    type = type,
                                    sql = sql,
                                    liveRowCount = rowCount,
                                    sampleRows = samples
                                )
                            )
                        }
                    }
                }
            }
        }.onFailure { e ->
            limitations.add("SQLite runtime query warning: ${e.message}. Binary header and page-level unallocated inspection still performed.")
        }

        // 3. Inspect unallocated cell space & freeblocks in B-tree leaf pages for deleted record remnants
        val remnants = scanSqliteUnallocatedPageRemnants(dbFile, pageSize)
        if (remnants.isEmpty()) {
            limitations.add("No printable deleted-record text remnants were identified in unallocated page regions (records may not have been deleted, or SQLite VACUUM / secure_delete zeroed unallocated space).")
        } else {
            limitations.add("Unallocated page strings represent raw byte remnants between the page header and cell content start offset; they do not guarantee complete row reconstruction.")
        }
        limitations.add("DeepVault never bypasses Android application sandboxes; only user-selected or accessible SQLite files can be inspected.")

        SqliteForensicReport(
            dbPath = dbFile.absolutePath,
            dbName = dbFile.name,
            fileSize = size,
            sha256 = sha256,
            isValidSqliteHeader = true,
            sqliteVersionString = sqliteVerStr,
            pageSizeBytes = pageSize,
            totalPagesInHeader = totalPages,
            textEncoding = textEncoding,
            freelistTrunkPage = freelistTrunk,
            freelistPageCount = freelistCount,
            fileChangeCounter = changeCounter,
            integrityCheckResult = integrityResult,
            walFilePresent = walFile.exists(),
            walFileSizeBytes = if (walFile.exists()) walFile.length() else 0L,
            journalFilePresent = journalFile.exists(),
            journalFileSizeBytes = if (journalFile.exists()) journalFile.length() else 0L,
            tables = tables,
            indexes = indexes,
            unallocatedRemnants = remnants,
            limitations = limitations
        )
    }

    /**
     * Deterministically inspects SQLite B-tree leaf table pages (flag 0x0D) for printable ASCII/UTF-8
     * remnants located in the unallocated gap (between end of cell pointer array and start of cell content area)
     * or within the page's linked freeblock list.
     */
    private fun scanSqliteUnallocatedPageRemnants(dbFile: File, pageSize: Int): List<SqliteUnallocatedRemnant> {
        if (pageSize < 512 || pageSize > 65536) return emptyList()
        val totalLen = dbFile.length()
        val numPages = (totalLen / pageSize).toInt().coerceAtMost(256)
        val remnants = mutableListOf<SqliteUnallocatedRemnant>()
        val pageBuf = ByteArray(pageSize)

        runCatching {
            RandomAccessFile(dbFile, "r").use { raf ->
                for (pageIdx in 0 until numPages) {
                    val pageStart = pageIdx.toLong() * pageSize.toLong()
                    raf.seek(pageStart)
                    val n = raf.read(pageBuf)
                    if (n < pageSize) break

                    val hdrOffset = if (pageIdx == 0) 100 else 0
                    if (hdrOffset + 8 >= pageSize) continue
                    val pageType = pageBuf[hdrOffset].toInt() and 0xFF
                    // 0x0D = Leaf table B-tree page
                    if (pageType == 0x0D) {
                        val bb = ByteBuffer.wrap(pageBuf).order(ByteOrder.BIG_ENDIAN)
                        val firstFreeblock = bb.getShort(hdrOffset + 1).toInt() and 0xFFFF
                        val cellCount = bb.getShort(hdrOffset + 3).toInt() and 0xFFFF
                        val cellContentStartRaw = bb.getShort(hdrOffset + 5).toInt() and 0xFFFF
                        val cellContentStart = if (cellContentStartRaw == 0) 65536 else cellContentStartRaw

                        val cellPtrArrayEnd = hdrOffset + 8 + (cellCount * 2)
                        // Scan unallocated gap between cellPtrArrayEnd and cellContentStart
                        if (cellContentStart > cellPtrArrayEnd && cellContentStart <= pageSize) {
                            val strings = extractPrintableStrings(pageBuf, cellPtrArrayEnd, cellContentStart - cellPtrArrayEnd)
                            if (strings.isNotEmpty()) {
                                remnants.add(
                                    SqliteUnallocatedRemnant(
                                        pageNumber = pageIdx + 1,
                                        byteOffset = pageStart + cellPtrArrayEnd,
                                        sourceRegion = "unallocated_cell_gap",
                                        extractedAsciiStrings = strings.take(10)
                                    )
                                )
                            }
                        }

                        // Walk freeblock chain on this page
                        var fbOffset = firstFreeblock
                        var hops = 0
                        while (fbOffset in (hdrOffset + 8)..(pageSize - 4) && hops < 16) {
                            hops++
                            val nextFb = bb.getShort(fbOffset).toInt() and 0xFFFF
                            val fbSize = bb.getShort(fbOffset + 2).toInt() and 0xFFFF
                            if (fbSize >= 6 && fbOffset + fbSize <= pageSize) {
                                val strings = extractPrintableStrings(pageBuf, fbOffset + 4, fbSize - 4)
                                if (strings.isNotEmpty()) {
                                    remnants.add(
                                        SqliteUnallocatedRemnant(
                                            pageNumber = pageIdx + 1,
                                            byteOffset = pageStart + fbOffset,
                                            sourceRegion = "page_freeblock_chain",
                                            extractedAsciiStrings = strings.take(10)
                                        )
                                    )
                                }
                            }
                            if (nextFb <= fbOffset) break
                            fbOffset = nextFb
                        }
                    } else if (pageIdx > 0 && pageType == 0x00) {
                        // Freelist or unallocated overflow/leaf page
                        val strings = extractPrintableStrings(pageBuf, 0, pageSize)
                        if (strings.isNotEmpty()) {
                            remnants.add(
                                SqliteUnallocatedRemnant(
                                    pageNumber = pageIdx + 1,
                                    byteOffset = pageStart,
                                    sourceRegion = "freelist_or_zero_header_page",
                                    extractedAsciiStrings = strings.take(10)
                                )
                            )
                        }
                    }
                }
            }
        }
        return remnants
    }

    private fun extractPrintableStrings(buf: ByteArray, offset: Int, length: Int, minChars: Int = 4): List<String> {
        val result = mutableListOf<String>()
        val sb = StringBuilder()
        val end = min(buf.size, offset + length)
        for (i in offset until end) {
            val b = buf[i].toInt() and 0xFF
            if (b in 32..126) {
                sb.append(b.toChar())
            } else {
                if (sb.length >= minChars) {
                    result.add(sb.toString())
                }
                sb.setLength(0)
            }
        }
        if (sb.length >= minChars) {
            result.add(sb.toString())
        }
        return result.distinct()
    }

    // =========================================================================
    // 6. MULTI-STRATEGY DUPLICATE & FILE RELATIONSHIP ENGINE (Section 5.E & 5.F)
    // =========================================================================

    suspend fun analyzeMultiStrategyDuplicates(
        files: List<File>
    ): List<MultiStrategyDuplicateCluster> = withContext(Dispatchers.IO) {
        val readable = files.filter { it.exists() && it.isFile && it.canRead() && it.length() > 0L }
        if (readable.size < 2) return@withContext emptyList()

        val members = readable.map { f ->
            currentCoroutineContext().ensureActive()
            val sha = ForensicAnalyzer.computeSha256Sync(f)
            val ext = f.extension.lowercase(Locale.US)
            val dHash = if (ext in setOf("jpg", "jpeg", "png", "webp", "bmp")) {
                computeImageDHashHex(f)
            } else null
            DuplicateMemberItem(
                path = f.absolutePath,
                name = f.name,
                sizeBytes = f.length(),
                sha256 = sha,
                dHashHex = dHash
            )
        }

        val clusters = mutableListOf<MultiStrategyDuplicateCluster>()
        var clusterSeq = 1

        // Strategy 1: Exact SHA-256 byte duplicates
        val bySha = members.groupBy { it.sha256 }.filter { it.key != "unavailable" && it.value.size > 1 }
        for ((sha, group) in bySha) {
            clusters.add(
                MultiStrategyDuplicateCluster(
                    clusterId = String.format(Locale.US, "DUP-EXACT-%03d", clusterSeq++),
                    strategy = DuplicateMatchStrategy.EXACT_SHA256,
                    signatureOrSizeKey = "SHA-256: $sha",
                    files = group
                )
            )
        }

        // Strategy 2: Same byte size but DIFFERENT SHA-256 (unproven identical, same-sized collision check)
        val bySize = members.groupBy { it.sizeBytes }.filter { it.value.size > 1 }
        for ((sizeBytes, group) in bySize) {
            val distinctHashes = group.map { it.sha256 }.distinct()
            if (distinctHashes.size > 1) {
                clusters.add(
                    MultiStrategyDuplicateCluster(
                        clusterId = String.format(Locale.US, "DUP-SIZE-%03d", clusterSeq++),
                        strategy = DuplicateMatchStrategy.SAME_SIZE_UNPROVEN,
                        signatureOrSizeKey = "Size: $sizeBytes bytes (${distinctHashes.size} distinct SHA-256 hashes)",
                        files = group
                    )
                )
            }
        }

        // Strategy 3: Visually similar images via 64-bit dHash (where SHA-256 differs)
        val withDHash = members.filter { it.dHashHex != null }
        val visited = mutableSetOf<String>()
        for (i in withDHash.indices) {
            val a = withDHash[i]
            if (a.path in visited) continue
            val group = mutableListOf(a)
            for (j in i + 1 until withDHash.size) {
                val b = withDHash[j]
                if (b.path in visited) continue
                if (a.sha256 != b.sha256 && hammingDistanceHex64(a.dHashHex!!, b.dHashHex!!) <= 10) {
                    group.add(b)
                }
            }
            if (group.size > 1) {
                group.forEach { visited.add(it.path) }
                clusters.add(
                    MultiStrategyDuplicateCluster(
                        clusterId = String.format(Locale.US, "DUP-VISUAL-%03d", clusterSeq++),
                        strategy = DuplicateMatchStrategy.PERCEPTUAL_SIMILAR_IMAGE,
                        signatureOrSizeKey = "dHash anchor: ${a.dHashHex}",
                        files = group
                    )
                )
            }
        }

        clusters
    }

    /**
     * Builds deterministic File Relationship edges across evidence records (Section 5.F).
     */
    fun discoverFileRelationships(
        records: List<ForensicEvidenceRecord>
    ): List<FileRelationshipEdge> {
        if (records.size < 2) return emptyList()
        val edges = mutableListOf<FileRelationshipEdge>()
        var edgeSeq = 1

        for (i in records.indices) {
            val a = records[i]
            for (j in i + 1 until records.size) {
                val b = records[j]

                // 1. Matching SHA-256
                if (a.sha256.length == 64 && a.sha256 == b.sha256) {
                    edges.add(
                        FileRelationshipEdge(
                            relationshipId = String.format(Locale.US, "REL-%03d", edgeSeq++),
                            sourceFileName = a.currentFilename,
                            sourcePath = a.sourceLocation ?: a.currentFilename,
                            targetFileName = b.currentFilename,
                            targetPath = b.sourceLocation ?: b.currentFilename,
                            relationshipType = RelationshipType.IDENTICAL_SHA256_CONTENT,
                            evidenceBasis = "Identical SHA-256 digest (${a.sha256.take(16)}…)",
                            confidenceNote = "Proven byte-level identity"
                        )
                    )
                }

                // 2. Thumbnail-to-Media correlation
                val aIsThumb = (a.sourceLocation?.contains("thumb", ignoreCase = true) == true) ||
                    a.currentFilename.contains("thumb", ignoreCase = true)
                val bIsThumb = (b.sourceLocation?.contains("thumb", ignoreCase = true) == true) ||
                    b.currentFilename.contains("thumb", ignoreCase = true)
                if (aIsThumb != bIsThumb) {
                    val thumb = if (aIsThumb) a else b
                    val parent = if (aIsThumb) b else a
                    val stemA = thumb.currentFilename.substringBeforeLast('.').lowercase(Locale.US).replace("thumb_", "").replace(".thumb", "")
                    val stemB = parent.currentFilename.substringBeforeLast('.').lowercase(Locale.US)
                    if (stemA.isNotBlank() && (stemB.contains(stemA) || stemA.contains(stemB))) {
                        edges.add(
                            FileRelationshipEdge(
                                relationshipId = String.format(Locale.US, "REL-%03d", edgeSeq++),
                                sourceFileName = thumb.currentFilename,
                                sourcePath = thumb.sourceLocation ?: "",
                                targetFileName = parent.currentFilename,
                                targetPath = parent.sourceLocation ?: "",
                                relationshipType = RelationshipType.THUMBNAIL_TO_PARENT_MEDIA,
                                evidenceBasis = "Thumbnail filename stem ('$stemA') matches media file ('$stemB')",
                                confidenceNote = "Correlated attribute (verify visually or via EXIF)"
                            )
                        )
                    }
                }

                // 3. Shared Camera Make/Model or Document Author
                val camA = listOfNotNull(a.imageMetadata?.cameraMake, a.imageMetadata?.cameraModel).joinToString(" ").trim()
                val camB = listOfNotNull(b.imageMetadata?.cameraMake, b.imageMetadata?.cameraModel).joinToString(" ").trim()
                if (camA.isNotBlank() && camA == camB) {
                    edges.add(
                        FileRelationshipEdge(
                            relationshipId = String.format(Locale.US, "REL-%03d", edgeSeq++),
                            sourceFileName = a.currentFilename,
                            sourcePath = a.sourceLocation ?: "",
                            targetFileName = b.currentFilename,
                            targetPath = b.sourceLocation ?: "",
                            relationshipType = RelationshipType.SHARED_CAMERA_OR_AUTHOR_METADATA,
                            evidenceBasis = "Both files contain embedded EXIF camera tag '$camA'",
                            confidenceNote = "Shared embedded metadata attribute (not proof of single device)"
                        )
                    )
                }

                val authA = a.documentMetadata?.author?.trim().orEmpty()
                val authB = b.documentMetadata?.author?.trim().orEmpty()
                if (authA.isNotBlank() && authA == authB) {
                    edges.add(
                        FileRelationshipEdge(
                            relationshipId = String.format(Locale.US, "REL-%03d", edgeSeq++),
                            sourceFileName = a.currentFilename,
                            sourcePath = a.sourceLocation ?: "",
                            targetFileName = b.currentFilename,
                            targetPath = b.sourceLocation ?: "",
                            relationshipType = RelationshipType.SHARED_CAMERA_OR_AUTHOR_METADATA,
                            evidenceBasis = "Both documents declare author '$authA'",
                            confidenceNote = "Shared embedded author tag"
                        )
                    )
                }

                // 4. Shared Accessible Directory
                if (!a.sourceLocation.isNullOrBlank() && a.sourceLocation == b.sourceLocation) {
                    edges.add(
                        FileRelationshipEdge(
                            relationshipId = String.format(Locale.US, "REL-%03d", edgeSeq++),
                            sourceFileName = a.currentFilename,
                            sourcePath = a.sourceLocation,
                            targetFileName = b.currentFilename,
                            targetPath = b.sourceLocation ?: "",
                            relationshipType = RelationshipType.SHARED_ACCESSIBLE_DIRECTORY,
                            evidenceBasis = "Co-located in accessible directory '${a.sourceLocation}'",
                            confidenceNote = "Observed filesystem location"
                        )
                    )
                }
            }
        }
        return edges
    }

    private fun computeImageDHashHex(file: File): String? = runCatching {
        val opts = BitmapFactory.Options().apply { inSampleSize = 8 }
        val bmp = BitmapFactory.decodeFile(file.absolutePath, opts) ?: return null
        val scaled = android.graphics.Bitmap.createScaledBitmap(bmp, 9, 8, true)
        var bits = 0L
        var bitPos = 0
        for (y in 0 until 8) {
            for (x in 0 until 8) {
                val p1 = scaled.getPixel(x, y)
                val p2 = scaled.getPixel(x + 1, y)
                val l1 = ((p1 shr 16 and 0xFF) * 299 + (p1 shr 8 and 0xFF) * 587 + (p1 and 0xFF) * 114)
                val l2 = ((p2 shr 16 and 0xFF) * 299 + (p2 shr 8 and 0xFF) * 587 + (p2 and 0xFF) * 114)
                if (l1 > l2) {
                    bits = bits or (1L shl bitPos)
                }
                bitPos++
            }
        }
        if (scaled != bmp) scaled.recycle()
        bmp.recycle()
        String.format(Locale.US, "%016x", bits)
    }.getOrNull()

    private fun hammingDistanceHex64(h1: String, h2: String): Int {
        val v1 = runCatching { java.lang.Long.parseUnsignedLong(h1, 16) }.getOrDefault(0L)
        val v2 = runCatching { java.lang.Long.parseUnsignedLong(h2, 16) }.getOrDefault(0L)
        return java.lang.Long.bitCount(v1 xor v2)
    }

    // =========================================================================
    // 7. MEDIA THUMBNAIL EXPLORER ENGINE (Section 5.I)
    // =========================================================================

    suspend fun inspectAccessibleThumbnails(
        allDiscoveredFiles: List<RecoverableFile>
    ): List<ThumbnailForensicItem> = withContext(Dispatchers.IO) {
        val photos = allDiscoveredFiles.filter { it.category == FileCategory.PHOTO }
        val thumbCandidates = photos.filter {
            it.path.contains(".thumbnails", ignoreCase = true) ||
                it.path.contains("thumb", ignoreCase = true) ||
                it.recoveryOrigin.contains("Thumb", ignoreCase = true) ||
                it.recoveryOrigin.contains("Cache", ignoreCase = true) ||
                it.size in 1024L..(120 * 1024L)
        }.take(60)

        val fullPhotos = photos.filter { it !in thumbCandidates && it.size > 120 * 1024L }

        thumbCandidates.mapNotNull { candidate ->
            currentCoroutineContext().ensureActive()
            val f = File(candidate.path)
            if (!f.exists() || !f.canRead()) return@mapNotNull null

            val sha = ForensicAnalyzer.computeSha256Sync(f)
            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            runCatching { BitmapFactory.decodeFile(f.absolutePath, bounds) }

            val stem = f.nameWithoutExtension.lowercase(Locale.US)
                .replace("thumb_", "")
                .replace(" carved_", "")

            val matchedParent = fullPhotos.firstOrNull { p ->
                val pStem = File(p.path).nameWithoutExtension.lowercase(Locale.US)
                stem.length >= 4 && (pStem.contains(stem) || stem.contains(pStem))
            }

            val struct = analyzeFileStructure(f)

            ThumbnailForensicItem(
                thumbnailPath = f.absolutePath,
                thumbnailName = f.name,
                sourceOrigin = candidate.recoveryOrigin,
                sizeBytes = f.length(),
                sha256 = sha,
                width = maxOf(0, bounds.outWidth),
                height = maxOf(0, bounds.outHeight),
                matchedParentMediaPath = matchedParent?.path,
                matchedParentMediaName = matchedParent?.name,
                relationshipBasis = if (matchedParent != null) {
                    "Filename stem correlation with accessible media '${matchedParent.name}'"
                } else {
                    "Orphan thumbnail / cached preview (original full-resolution media not found in accessible storage)"
                },
                recoveryClassification = struct.recoveryClassification,
                limitationsNote = "Only thumbnails in accessible shared storage (.thumbnails) or carved from accessible .thumbdata blobs are shown. Private app sandbox caches cannot be read without verified root privileges."
            )
        }
    }

    // =========================================================================
    // 8. NON-DESTRUCTIVE FILE REPAIR LAB ENGINE (Section 6)
    // =========================================================================

    /**
     * Performs safe, non-destructive header/trailer/container repair on supported formats
     * (JPEG missing EOI, PNG missing IEND, RIFF/WebP/WAV payload length mismatch, PDF missing %%EOF).
     *
     * Strictly follows Section 6 rules:
     * 1. Never overwrites the original file.
     * 2. Saves repaired output as a new file in [outputDir].
     * 3. Records the exact repair method.
     * 4. Preserves original and output SHA-256 hashes.
     * 5. Records warnings and unsuccessful repairs honestly.
     * 6. Never claims damaged/missing pixel or document content was restored when only the container trailer was closed.
     */
    suspend fun repairFileNonDestructive(
        sourceFile: File,
        outputDir: File
    ): FileRepairReport = withContext(Dispatchers.IO) {
        outputDir.mkdirs()
        val beforeAnalysis = analyzeFileStructure(sourceFile)
        val originalSha = ForensicAnalyzer.computeSha256Sync(sourceFile)

        if (!sourceFile.exists() || !sourceFile.canRead() || sourceFile.length() == 0L) {
            return@withContext FileRepairReport(
                originalPath = sourceFile.absolutePath,
                originalName = sourceFile.name,
                originalSize = 0L,
                originalSha256 = originalSha,
                detectedFormat = beforeAnalysis.detectedFormat,
                diagnosisBefore = beforeAnalysis,
                repairMethodApplied = "none_source_unreadable_or_empty",
                repairOutcome = FileRepairOutcome.REPAIR_UNSUPPORTED_OR_FAILED,
                repairedOutputFile = null,
                repairedSize = null,
                repairedSha256 = null,
                validationAfter = null,
                warnings = listOf("Source file is missing, unreadable, or 0 bytes. No repair possible."),
                honestDisclosure = "Original file was not modified. Empty or unreadable files contain no recoverable payload."
            )
        }

        if (!beforeAnalysis.isTruncated && beforeAnalysis.structuralErrors.isEmpty()) {
            return@withContext FileRepairReport(
                originalPath = sourceFile.absolutePath,
                originalName = sourceFile.name,
                originalSize = sourceFile.length(),
                originalSha256 = originalSha,
                detectedFormat = beforeAnalysis.detectedFormat,
                diagnosisBefore = beforeAnalysis,
                repairMethodApplied = "none_structure_already_valid",
                repairOutcome = FileRepairOutcome.NO_REPAIR_NEEDED,
                repairedOutputFile = null,
                repairedSize = null,
                repairedSha256 = null,
                validationAfter = beforeAnalysis,
                warnings = emptyList(),
                honestDisclosure = "File already passes header, footer, and container validation checks. No modification or duplicate output was needed."
            )
        }

        val baseName = sourceFile.nameWithoutExtension.ifBlank { "evidence" }
        val ext = sourceFile.extension.ifBlank {
            when (beforeAnalysis.detectedFormat) {
                "JPEG" -> "jpg"
                "PNG" -> "png"
                "WEBP" -> "webp"
                "PDF" -> "pdf"
                else -> "bin"
            }
        }
        val repairedFile = File(outputDir, "${baseName}_repaired_${System.currentTimeMillis() % 100000}.$ext")
        val warnings = mutableListOf<String>()

        when (beforeAnalysis.detectedFormat) {
            "JPEG" -> {
                if (beforeAnalysis.footerValid == false) {
                    // Copy original bytes and append JPEG EOI (0xFF, 0xD9)
                    sourceFile.inputStream().use { input ->
                        FileOutputStream(repairedFile).use { output ->
                            input.copyTo(output, STREAM_CHUNK)
                            output.write(byteArrayOf(0xFF.toByte(), 0xD9.toByte()))
                        }
                    }
                    val afterAnalysis = analyzeFileStructure(repairedFile)
                    val repairedSha = ForensicAnalyzer.computeSha256Sync(repairedFile)
                    warnings.add("Appended 2-byte JPEG EOI (0xFFD9) trailer marker to close the entropy scan container.")
                    warnings.add("Missing scanlines truncated before EOF cannot be synthesized; existing decoded MCU blocks are preserved.")
                    return@withContext FileRepairReport(
                        originalPath = sourceFile.absolutePath,
                        originalName = sourceFile.name,
                        originalSize = sourceFile.length(),
                        originalSha256 = originalSha,
                        detectedFormat = "JPEG",
                        diagnosisBefore = beforeAnalysis,
                        repairMethodApplied = "jpeg_eoi_trailer_reconstruction",
                        repairOutcome = if (afterAnalysis.recoveryClassification == RecoveryClassification.RECOVERED) {
                            FileRepairOutcome.REPAIRED_CONTAINER_VALIDATED
                        } else {
                            FileRepairOutcome.PARTIAL_REPAIR_WARNING
                        },
                        repairedOutputFile = repairedFile,
                        repairedSize = repairedFile.length(),
                        repairedSha256 = repairedSha,
                        validationAfter = afterAnalysis,
                        warnings = warnings,
                        honestDisclosure = "Original file left untouched. Repaired copy closes the JPEG container with 0xFFD9 so decoders can render available scanlines without inventing missing pixels."
                    )
                }
            }

            "PNG" -> {
                if (beforeAnalysis.footerValid == false && beforeAnalysis.headerValid) {
                    // Copy original bytes and append standard 12-byte IEND chunk: 00 00 00 00 + "IEND" + AE 42 60 82
                    val iendChunk = byteArrayOf(
                        0x00, 0x00, 0x00, 0x00,
                        0x49, 0x45, 0x4E, 0x44,
                        0xAE.toByte(), 0x42, 0x60, 0x82.toByte()
                    )
                    sourceFile.inputStream().use { input ->
                        FileOutputStream(repairedFile).use { output ->
                            input.copyTo(output, STREAM_CHUNK)
                            output.write(iendChunk)
                        }
                    }
                    val afterAnalysis = analyzeFileStructure(repairedFile)
                    val repairedSha = ForensicAnalyzer.computeSha256Sync(repairedFile)
                    warnings.add("Appended canonical 12-byte PNG IEND chunk (CRC32 0xAE426082) to new output file.")
                    warnings.add("If an IDAT deflate stream was cut mid-chunk, image decoders may still report partial scanlines.")
                    return@withContext FileRepairReport(
                        originalPath = sourceFile.absolutePath,
                        originalName = sourceFile.name,
                        originalSize = sourceFile.length(),
                        originalSha256 = originalSha,
                        detectedFormat = "PNG",
                        diagnosisBefore = beforeAnalysis,
                        repairMethodApplied = "png_iend_chunk_reconstruction",
                        repairOutcome = if (afterAnalysis.footerValid == true) {
                            FileRepairOutcome.REPAIRED_CONTAINER_VALIDATED
                        } else {
                            FileRepairOutcome.PARTIAL_REPAIR_WARNING
                        },
                        repairedOutputFile = repairedFile,
                        repairedSize = repairedFile.length(),
                        repairedSha256 = repairedSha,
                        validationAfter = afterAnalysis,
                        warnings = warnings,
                        honestDisclosure = "Original file left untouched. Repaired copy appends the missing PNG IEND trailer chunk; truncated IDAT compressed data is not fabricated."
                    )
                }
            }

            "WEBP" -> {
                if (sourceFile.length() >= 16L) {
                    // Reconcile RIFF 32-bit little-endian size header at offset 4 with actual file length - 8
                    sourceFile.copyTo(repairedFile, overwrite = true)
                    val actualPayload = (repairedFile.length() - 8L).coerceAtLeast(0L).toInt()
                    RandomAccessFile(repairedFile, "rw").use { raf ->
                        raf.seek(4L)
                        val leBytes = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(actualPayload).array()
                        raf.write(leBytes)
                    }
                    val afterAnalysis = analyzeFileStructure(repairedFile)
                    val repairedSha = ForensicAnalyzer.computeSha256Sync(repairedFile)
                    warnings.add("Updated 32-bit RIFF container size field at offset 0x04 to match actual available byte length ($actualPayload bytes).")
                    return@withContext FileRepairReport(
                        originalPath = sourceFile.absolutePath,
                        originalName = sourceFile.name,
                        originalSize = sourceFile.length(),
                        originalSha256 = originalSha,
                        detectedFormat = "WEBP",
                        diagnosisBefore = beforeAnalysis,
                        repairMethodApplied = "riff_header_size_reconciliation",
                        repairOutcome = FileRepairOutcome.REPAIRED_CONTAINER_VALIDATED,
                        repairedOutputFile = repairedFile,
                        repairedSize = repairedFile.length(),
                        repairedSha256 = repairedSha,
                        validationAfter = afterAnalysis,
                        warnings = warnings,
                        honestDisclosure = "Original file left untouched. Reconciled the RIFF header size field with actual available bytes; any missing bitstream data at EOF remains absent."
                    )
                }
            }

            "PDF" -> {
                if (beforeAnalysis.footerValid == false) {
                    sourceFile.inputStream().use { input ->
                        FileOutputStream(repairedFile).use { output ->
                            input.copyTo(output, STREAM_CHUNK)
                            output.write("\n%%EOF\n".toByteArray(StandardCharsets.US_ASCII))
                        }
                    }
                    val afterAnalysis = analyzeFileStructure(repairedFile)
                    val repairedSha = ForensicAnalyzer.computeSha256Sync(repairedFile)
                    warnings.add("Appended '\\n%%EOF\\n' trailer marker to new PDF copy.")
                    if (afterAnalysis.structuralErrors.isNotEmpty()) {
                        warnings.add("Note: PDF cross-reference table (startxref) is still incomplete; tolerant PDF readers can index objects sequentially.")
                    }
                    return@withContext FileRepairReport(
                        originalPath = sourceFile.absolutePath,
                        originalName = sourceFile.name,
                        originalSize = sourceFile.length(),
                        originalSha256 = originalSha,
                        detectedFormat = "PDF",
                        diagnosisBefore = beforeAnalysis,
                        repairMethodApplied = "pdf_eof_trailer_append",
                        repairOutcome = FileRepairOutcome.PARTIAL_REPAIR_WARNING,
                        repairedOutputFile = repairedFile,
                        repairedSize = repairedFile.length(),
                        repairedSha256 = repairedSha,
                        validationAfter = afterAnalysis,
                        warnings = warnings,
                        honestDisclosure = "Original file left untouched. Appended %%EOF trailer marker; missing indirect objects or xref tables were not fabricated."
                    )
                }
            }
        }

        return@withContext FileRepairReport(
            originalPath = sourceFile.absolutePath,
            originalName = sourceFile.name,
            originalSize = sourceFile.length(),
            originalSha256 = originalSha,
            detectedFormat = beforeAnalysis.detectedFormat,
            diagnosisBefore = beforeAnalysis,
            repairMethodApplied = "unsupported_for_damage_type",
            repairOutcome = FileRepairOutcome.REPAIR_UNSUPPORTED_OR_FAILED,
            repairedOutputFile = null,
            repairedSize = null,
            repairedSha256 = null,
            validationAfter = null,
            warnings = listOf(
                "Safe deterministic repair is not available for ${beforeAnalysis.detectedFormat} with errors: ${beforeAnalysis.structuralErrors.joinToString("; ")}"
            ),
            honestDisclosure = "Original file was not modified. DeepVault refuses to fabricate missing payload or overwrite damaged containers when deterministic reconstruction is not supported."
        )
    }
}
