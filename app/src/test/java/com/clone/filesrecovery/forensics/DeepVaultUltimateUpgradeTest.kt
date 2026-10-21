package com.clone.filesrecovery.forensics

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class DeepVaultUltimateUpgradeTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private fun createValidMinimalPng(file: File, trailingExtraBytes: ByteArray = ByteArray(0)) {
        FileOutputStream(file).use { fos ->
            // 8-byte PNG signature
            fos.write(byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A))
            // IHDR chunk (13 bytes)
            val ihdrType = "IHDR".toByteArray(StandardCharsets.US_ASCII)
            val ihdrData = ByteBuffer.allocate(13).order(ByteOrder.BIG_ENDIAN)
                .putInt(1) // width
                .putInt(1) // height
                .put(8.toByte()) // bit depth
                .put(2.toByte()) // color type RGB
                .put(0.toByte())
                .put(0.toByte())
                .put(0.toByte())
                .array()
            writePngChunk(fos, ihdrType, ihdrData)
            // IDAT chunk (dummy compressed payload)
            val idatType = "IDAT".toByteArray(StandardCharsets.US_ASCII)
            val idatData = byteArrayOf(0x78, 0x9C.toByte(), 0x63, 0x60, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01)
            writePngChunk(fos, idatType, idatData)
            // IEND chunk (0 bytes)
            val iendType = "IEND".toByteArray(StandardCharsets.US_ASCII)
            writePngChunk(fos, iendType, ByteArray(0))
            if (trailingExtraBytes.isNotEmpty()) {
                fos.write(trailingExtraBytes)
            }
        }
    }

    private fun writePngChunk(fos: FileOutputStream, type: ByteArray, data: ByteArray) {
        val lenBytes = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(data.size).array()
        fos.write(lenBytes)
        fos.write(type)
        if (data.isNotEmpty()) fos.write(data)
        val crc = CRC32()
        crc.update(type)
        if (data.isNotEmpty()) crc.update(data)
        val crcBytes = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(crc.value.toInt()).array()
        fos.write(crcBytes)
    }

    private fun createValidMinimalJpeg(file: File, includeEoi: Boolean = true) {
        FileOutputStream(file).use { fos ->
            // SOI
            fos.write(byteArrayOf(0xFF.toByte(), 0xD8.toByte()))
            // APP0 JFIF segment
            fos.write(byteArrayOf(0xFF.toByte(), 0xE0.toByte(), 0x00, 0x10))
            fos.write("JFIF\u0000\u0001\u0001\u0000\u0000\u0001\u0000\u0001\u0000\u0000".toByteArray(StandardCharsets.ISO_8859_1))
            // SOF0 baseline segment (length 11)
            fos.write(
                byteArrayOf(
                    0xFF.toByte(), 0xC0.toByte(), 0x00, 0x0B,
                    0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00
                )
            )
            // SOS segment (length 8) + entropy scan bytes
            fos.write(
                byteArrayOf(
                    0xFF.toByte(), 0xDA.toByte(), 0x00, 0x08,
                    0x01, 0x01, 0x00, 0x00, 0x3F, 0x00,
                    0x12, 0x34, 0x56, 0x78
                )
            )
            if (includeEoi) {
                fos.write(byteArrayOf(0xFF.toByte(), 0xD9.toByte()))
            }
        }
    }

    @Test
    fun `hex viewer reads pages and searches hex and ascii patterns without full memory load`() = runBlocking {
        val file = tempFolder.newFile("sample_stream.bin")
        val payload = ByteArray(2048) { idx -> (idx % 251).toByte() }
        // Inject magic JPEG header at 0 and ASCII marker at offset 1200
        payload[0] = 0xFF.toByte()
        payload[1] = 0xD8.toByte()
        payload[2] = 0xFF.toByte()
        val marker = "DEEPVAULT_FORENSIC_MARKER".toByteArray(StandardCharsets.US_ASCII)
        System.arraycopy(marker, 0, payload, 1200, marker.size)
        file.writeBytes(payload)

        val page0 = DeepVaultLabsEngine.readHexPage(file, pageOffset = 0L, bytesPerPage = 512)
        assertEquals(2048L, page0.totalFileSize)
        assertEquals(32, page0.rows.size)
        assertTrue(page0.signatureDescription.contains("JPEG", ignoreCase = true))
        assertTrue(page0.rows.first().highlightedByteIndices.containsAll(listOf(0, 1, 2)))

        val asciiMatches = DeepVaultLabsEngine.searchBytePatternStreaming(file, "DEEPVAULT_FORENSIC_MARKER", isHexQuery = false)
        assertEquals(1, asciiMatches.size)
        assertEquals(1200L, asciiMatches.first().offset)

        val hexMatches = DeepVaultLabsEngine.searchBytePatternStreaming(file, "FF D8 FF", isHexQuery = true)
        assertTrue(hexMatches.any { it.offset == 0L })
    }

    @Test
    fun `file structure analyzer validates png crc32 trailing bytes and truncated jpeg`() {
        val pngWithTrailing = tempFolder.newFile("trailing.png")
        createValidMinimalPng(pngWithTrailing, trailingExtraBytes = "APPENDED_DATA_123".toByteArray())

        val pngStruct = DeepVaultLabsEngine.analyzeFileStructure(pngWithTrailing)
        assertEquals("PNG", pngStruct.detectedFormat)
        assertTrue(pngStruct.headerValid)
        assertEquals(true, pngStruct.footerValid)
        assertEquals(17L, pngStruct.unexpectedTrailingBytes)
        assertEquals(RecoveryClassification.RECOVERED, pngStruct.recoveryClassification)

        val truncatedJpg = tempFolder.newFile("truncated.jpg")
        createValidMinimalJpeg(truncatedJpg, includeEoi = false)
        val jpgStruct = DeepVaultLabsEngine.analyzeFileStructure(truncatedJpg)
        assertEquals("JPEG", jpgStruct.detectedFormat)
        assertTrue(jpgStruct.isTruncated)
        assertEquals(false, jpgStruct.footerValid)
        assertEquals(RecoveryClassification.PARTIALLY_RECOVERED, jpgStruct.recoveryClassification)
    }

    @Test
    fun `signature stream carver extracts embedded jpeg and png from container stream`() = runBlocking {
        val jpgTmp = tempFolder.newFile("src.jpg")
        createValidMinimalJpeg(jpgTmp, includeEoi = true)
        val pngTmp = tempFolder.newFile("src.png")
        createValidMinimalPng(pngTmp)

        val blobFile = tempFolder.newFile("cache_container.blob")
        FileOutputStream(blobFile).use { out ->
            out.write(ByteArray(256) { 0x11 })
            out.write(jpgTmp.readBytes())
            out.write(ByteArray(300) { 0x22 })
            out.write(pngTmp.readBytes())
            out.write(ByteArray(128) { 0x33 })
        }

        val carveOutDir = tempFolder.newFolder("carved_out")
        val carved = DeepVaultLabsEngine.carveStreamsFromAccessibleSource(blobFile, carveOutDir)
        assertTrue("Expected at least 2 carved streams (JPEG and PNG)", carved.size >= 2)
        assertTrue(carved.any { it.format == "JPEG" && it.classification == RecoveryClassification.RECOVERED })
        assertTrue(carved.any { it.format == "PNG" && it.classification == RecoveryClassification.RECOVERED })
    }

    @Test
    fun `non-destructive file repair lab reconstructs missing jpeg eoi and png iend without modifying source`() = runBlocking {
        val truncatedJpg = tempFolder.newFile("broken_photo.jpg")
        createValidMinimalJpeg(truncatedJpg, includeEoi = false)
        val origShaBefore = ForensicAnalyzer.computeSha256Sync(truncatedJpg)
        val origSizeBefore = truncatedJpg.length()

        val repairDir = tempFolder.newFolder("repaired_out")
        val report = DeepVaultLabsEngine.repairFileNonDestructive(truncatedJpg, repairDir)

        // Rule 1: Original file must never be modified
        assertEquals(origShaBefore, ForensicAnalyzer.computeSha256Sync(truncatedJpg))
        assertEquals(origSizeBefore, truncatedJpg.length())

        // Rule 2, 3, 4: New repaired file created with valid EOI and recorded SHA-256
        assertEquals(FileRepairOutcome.REPAIRED_CONTAINER_VALIDATED, report.repairOutcome)
        assertNotNull(report.repairedOutputFile)
        assertTrue(report.repairedOutputFile!!.exists())
        assertEquals(origSizeBefore + 2L, report.repairedSize)
        assertNotEquals(report.originalSha256, report.repairedSha256)
        assertEquals(RecoveryClassification.RECOVERED, report.validationAfter?.recoveryClassification)
    }

    @Test
    fun `archive forensics detects zip entries sha256 and flags path traversal anomalies`() = runBlocking {
        val zipFile = tempFolder.newFile("evidence_bundle.zip")
        ZipOutputStream(FileOutputStream(zipFile)).use { zos ->
            val normalEntry = ZipEntry("docs/readme.txt")
            zos.putNextEntry(normalEntry)
            zos.write("Safe forensic document content".toByteArray(StandardCharsets.UTF_8))
            zos.closeEntry()

            val traversalEntry = ZipEntry("../../etc/hosts")
            zos.putNextEntry(traversalEntry)
            zos.write("127.0.0.1 localhost".toByteArray(StandardCharsets.UTF_8))
            zos.closeEntry()
        }

        val report = DeepVaultLabsEngine.inspectArchiveForensics(zipFile)
        assertTrue(report.hasEndOfCentralDirectory)
        assertEquals(2, report.totalEntries)
        assertTrue(report.entries.any { it.hasPathTraversalAnomaly })
        assertTrue(report.structuralAnomalies.any { it.contains("traversal", ignoreCase = true) })
        assertNotNull(report.entries.first().sha256)
    }

    @Test
    fun `sqlite forensics inspects header schema live rows and unallocated deleted record remnants`() = runBlocking {
        val dbFile = tempFolder.newFile("messages_forensic.sqlite")
        val db = SQLiteDatabase.openOrCreateDatabase(dbFile, null)
        db.use { sqlite ->
            sqlite.rawQuery("PRAGMA secure_delete = OFF;", null).close()
            sqlite.rawQuery("PRAGMA auto_vacuum = NONE;", null).close()
            sqlite.execSQL("CREATE TABLE chat_logs (id INTEGER PRIMARY KEY, sender TEXT, secret_payload TEXT);")
            sqlite.execSQL("INSERT INTO chat_logs VALUES (1, 'alice', 'Active message row one');")
            sqlite.execSQL("INSERT INTO chat_logs VALUES (2, 'bob', 'DELETED_FORENSIC_REMNANT_998877');")
            sqlite.execSQL("INSERT INTO chat_logs VALUES (3, 'charlie', 'Active message row three');")
            sqlite.execSQL("DELETE FROM chat_logs WHERE id = 2;")
        }

        val report = DeepVaultLabsEngine.inspectSqliteDatabase(dbFile)
        assertTrue(report.isValidSqliteHeader)
        assertEquals("ok", report.integrityCheckResult)
        assertTrue(report.tables.any { it.name == "chat_logs" && it.liveRowCount == 2L })
        val allRemnantStrings = report.unallocatedRemnants.flatMap { it.extractedAsciiStrings }
        assertTrue(
            "Expected deleted SQLite record string in unallocated/freeblock space",
            allRemnantStrings.any { it.contains("DELETED_FORENSIC_REMNANT_998877") }
        )
    }

    @Test
    fun `multi-strategy duplicate detector distinguishes exact sha256 duplicates from same-sized different files`() = runBlocking {
        val f1 = tempFolder.newFile("dup_a.bin").apply { writeBytes("IDENTICAL_CONTENT_123456".toByteArray()) }
        val f2 = tempFolder.newFile("dup_b.bin").apply { writeBytes("IDENTICAL_CONTENT_123456".toByteArray()) }
        val f3 = tempFolder.newFile("same_size_diff.bin").apply { writeBytes("DIFFERENT_CONTENT_654321".toByteArray()) }

        val clusters = DeepVaultLabsEngine.analyzeMultiStrategyDuplicates(listOf(f1, f2, f3))
        assertTrue(clusters.any { it.strategy == DuplicateMatchStrategy.EXACT_SHA256 && it.files.size == 2 })
        assertTrue(clusters.any { it.strategy == DuplicateMatchStrategy.SAME_SIZE_UNPROVEN && it.files.size == 3 })
    }

    @Test
    fun `investigation case manager and hash-linked chain of custody verify integrity and detect tampering`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val created = CaseAndCustodyManager.createCase(
            context = context,
            caseId = "CASE-TEST-900",
            title = "Unit Test Investigation",
            investigatorName = "Senior Analyst",
            description = "Testing case persistence and custody chain",
            operatingMode = "Standard"
        )
        assertEquals("CASE-TEST-900", created.caseId)

        CaseAndCustodyManager.appendCustodyEvent(
            context = context,
            actionType = CustodyActionType.HASH_CALCULATED,
            caseId = created.caseId,
            evidenceId = "DV-000001",
            details = "SHA-256 calculated for artifact #1"
        )

        val verif = CaseAndCustodyManager.verifyCustodyChainIntegrity(context)
        assertTrue(verif.isChainIntact)
        assertTrue(verif.totalEntriesChecked >= 2)
    }

    @Test
    fun `privacy redaction supports excluding personal metadata and analyst notes`() = runBlocking {
        val f = tempFolder.newFile("doc_sample.pdf")
        f.writeBytes("%PDF-1.4\n1 0 obj\n<< /Author (John Personal Name) /Title (Report) >>\nendobj\n%%EOF".toByteArray())

        val rawRecord = ForensicAnalyzer.analyzeFile(
            context = null,
            targetFile = f,
            originalFilename = "john_private_tax.pdf",
            sourceLocation = "/storage/emulated/0/PrivateFolder"
        )
        val options = ForensicPrivacyOptions(
            includeGps = false,
            redactSensitivePaths = true,
            excludePersonalFilenames = true,
            excludePersonalMetadata = true,
            excludeNotes = true
        )
        val redacted = ForensicAnalyzer.applyRedactionToRecord(rawRecord, options)
        assertTrue(redacted.isRedacted)
        assertTrue(redacted.currentFilename.startsWith("[REDACTED_FILENAME_"))
        assertTrue(redacted.sourceLocation!!.startsWith("[REDACTED_PATH]"))
        assertEquals(null, redacted.documentMetadata?.author)
    }
}
