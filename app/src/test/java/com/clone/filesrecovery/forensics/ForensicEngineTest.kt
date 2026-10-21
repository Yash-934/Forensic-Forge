package com.clone.filesrecovery.forensics

import kotlinx.coroutines.test.runTest
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ForensicEngineTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Before
    fun setUp() {
        EvidenceIdRegistry.resetForTest()
    }

    @Test
    fun `streaming hash calculation matches known SHA-256 MD5 and SHA-1 vectors`() = runTest {
        val file = tempFolder.newFile("sample.txt")
        file.writeBytes("abc".toByteArray(StandardCharsets.US_ASCII))

        val hashes = ForensicAnalyzer.computeHashesStreaming(file)
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            hashes.sha256
        )
        assertEquals("900150983cd24fb0d6963f7d28e17f72", hashes.md5)
        assertEquals("a9993e364706816aba3e25717850c26c9cd0d89d", hashes.sha1)
    }

    @Test
    fun `magic byte inspection validates complete vs truncated JPEG and detects extension mismatch`() = runTest {
        // 1. Valid complete JPEG with FF D8 FF header and FF D9 EOI marker
        val validJpg = tempFolder.newFile("photo.jpg")
        val jpgBytes = byteArrayOf(
            0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte(), 0xE0.toByte(),
            0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
            0x01, 0x02, 0x03, 0x04, 0xFF.toByte(), 0xD9.toByte()
        )
        validJpg.writeBytes(jpgBytes)

        val validRes = ForensicAnalyzer.inspectMagicAndStructure(validJpg, "jpg")
        assertEquals("JPEG", validRes.detectedFormat)
        assertEquals("image/jpeg", validRes.detectedMime)
        assertEquals("passed", validRes.structureCheck)
        assertEquals("complete", validRes.completenessStatus)
        assertFalse(validRes.extensionMismatch)

        // 2. Truncated JPEG missing FF D9 EOI marker
        val truncatedJpg = tempFolder.newFile("carved_partial.jpg")
        truncatedJpg.writeBytes(jpgBytes.dropLast(2).toByteArray())
        val truncRes = ForensicAnalyzer.inspectMagicAndStructure(truncatedJpg, "jpg")
        assertEquals("JPEG", truncRes.detectedFormat)
        assertEquals("warning", truncRes.structureCheck)
        assertEquals("partial", truncRes.completenessStatus)
        assertTrue(truncRes.corruptionIndicators.contains("missing_jpeg_eoi_marker"))

        // 3. Extension mismatch: JPEG binary header saved with .pdf extension
        val disguisedFile = tempFolder.newFile("invoice.pdf")
        disguisedFile.writeBytes(jpgBytes)
        val mismatchRecord = ForensicAnalyzer.analyzeFile(
            context = null,
            targetFile = disguisedFile,
            scanSessionId = "SESSION-TEST"
        )
        assertEquals("JPEG", mismatchRecord.detectedFormat)
        assertTrue(mismatchRecord.extensionMismatch)
        assertTrue(mismatchRecord.findings.any { it.category == "extension_mismatch" })
    }

    @Test
    fun `PDF parser extracts Author CreationDate PageCount and DigitalSignature status deterministically`() = runTest {
        val pdfFile = tempFolder.newFile("contract.pdf")
        val pdfContent = """
            %PDF-1.7
            1 0 obj
            << /Type /Catalog /Pages 2 0 R >>
            endobj
            2 0 obj
            << /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>
            endobj
            3 0 obj
            << /Type /Page /Parent 2 0 R >>
            endobj
            4 0 obj
            << /Type /Page /Parent 2 0 R >>
            endobj
            5 0 obj
            << /Author (Alice Forensic Analyst) /Creator (DeepVault Writer) /Producer (DeepVault PDF 2.0) /Title (Forensic Audit) /CreationDate (D:20261020143005Z) /ModDate (D:20261020153000+05'30') >>
            endobj
            6 0 obj
            << /Type /Sig /ByteRange [0 100 200 300] >>
            endobj
            %%EOF
        """.trimIndent()
        pdfFile.writeBytes(pdfContent.toByteArray(StandardCharsets.ISO_8859_1))

        val record = ForensicAnalyzer.analyzeFile(
            context = null,
            targetFile = pdfFile,
            scanSessionId = "SESSION-PDF"
        )

        assertEquals("PDF", record.detectedFormat)
        assertEquals("passed", record.structureCheck)
        assertNotNull(record.documentMetadata)
        assertEquals("Alice Forensic Analyst", record.documentMetadata?.author)
        assertEquals("DeepVault Writer", record.documentMetadata?.creatorOrLastModifiedBy)
        assertEquals(2, record.documentMetadata?.pageCount)
        assertEquals("present_unverified_chain", record.documentMetadata?.digitalSignatureStatus)
        assertTrue(record.timeline.any { it.eventType == "pdf_creation_date" && it.timezoneStatus == "explicit_utc" })
        assertTrue(record.timeline.any { it.eventType == "pdf_modification_date" && it.timezoneStatus == "explicit_offset" })
    }

    @Test
    fun `DOCX OOXML and WAV RIFF parsers extract embedded metadata and audio header parameters`() = runTest {
        // 1. Create a valid DOCX (ZIP container with word/document.xml, docProps/core.xml, docProps/app.xml)
        val docxFile = tempFolder.newFile("report.docx")
        FileOutputStream(docxFile).use { fos ->
            ZipOutputStream(fos).use { zos ->
                zos.putNextEntry(ZipEntry("word/document.xml"))
                zos.write("<w:document><w:body/></w:document>".toByteArray())
                zos.closeEntry()

                zos.putNextEntry(ZipEntry("docProps/core.xml"))
                zos.write(
                    """
                    <cp:coreProperties>
                        <dc:title>Incident Summary</dc:title>
                        <dc:creator>Bob Investigator</dc:creator>
                        <cp:lastModifiedBy>Carol Reviewer</cp:lastModifiedBy>
                        <dcterms:created>2026-10-19T09:15:00Z</dcterms:created>
                    </cp:coreProperties>
                    """.trimIndent().toByteArray()
                )
                zos.closeEntry()

                zos.putNextEntry(ZipEntry("docProps/app.xml"))
                zos.write("<Properties><Pages>7</Pages><Application>LibreOffice</Application></Properties>".toByteArray())
                zos.closeEntry()
            }
        }

        val docxRec = ForensicAnalyzer.analyzeFile(null, docxFile)
        assertEquals("DOCX", docxRec.detectedFormat)
        assertEquals("passed", docxRec.structureCheck)
        assertEquals("Bob Investigator", docxRec.documentMetadata?.author)
        assertEquals("Carol Reviewer", docxRec.documentMetadata?.creatorOrLastModifiedBy)
        assertEquals(7, docxRec.documentMetadata?.pageCount)
        assertEquals("LibreOffice", docxRec.documentMetadata?.producerOrApplication)

        // 2. Create a valid 44.1 kHz stereo WAV file
        val wavFile = tempFolder.newFile("voice_note.wav")
        val pcmDataSize = 44100 * 4 // 1 second of 16-bit stereo
        val totalRiffChunkSize = 36 + pcmDataSize
        val header = ByteBuffer.allocate(44).order(ByteOrder.LITTLE_ENDIAN).apply {
            put("RIFF".toByteArray(StandardCharsets.US_ASCII))
            putInt(totalRiffChunkSize)
            put("WAVE".toByteArray(StandardCharsets.US_ASCII))
            put("fmt ".toByteArray(StandardCharsets.US_ASCII))
            putInt(16) // PCM fmt chunk size
            putShort(1) // AudioFormat = 1 (PCM)
            putShort(2) // NumChannels = 2 (Stereo)
            putInt(44100) // SampleRate = 44100 Hz
            putInt(44100 * 4) // ByteRate = 176400 B/s
            putShort(4) // BlockAlign
            putShort(16) // BitsPerSample
            put("data".toByteArray(StandardCharsets.US_ASCII))
            putInt(pcmDataSize)
        }.array()
        val fullWav = ByteArrayOutputStream().apply {
            write(header)
            write(ByteArray(pcmDataSize))
        }.toByteArray()
        wavFile.writeBytes(fullWav)

        val wavRec = ForensicAnalyzer.analyzeFile(null, wavFile)
        assertEquals("WAV", wavRec.detectedFormat)
        assertEquals("passed", wavRec.structureCheck)
        assertEquals(44100, wavRec.audioMetadata?.sampleRateHz)
        assertEquals(2, wavRec.audioMetadata?.channelCount)
    }

    @Test
    fun `case report detects duplicates applies non-destructive privacy redaction and verifies SHA-256 manifest`() = runTest {
        val dir = tempFolder.newFolder("sensitive_user_folder")
        val f1 = File(dir, "secret_passport_scan.jpg")
        val f2 = File(dir, "secret_passport_copy.jpg")
        val payload = byteArrayOf(
            0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte(), 0xE0.toByte(),
            0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
            0x11, 0x22, 0x33, 0x44, 0xFF.toByte(), 0xD9.toByte()
        )
        f1.writeBytes(payload)
        f2.writeBytes(payload)

        val r1 = ForensicAnalyzer.analyzeFile(null, f1, sourceLocation = dir.absolutePath)
        val r2 = ForensicAnalyzer.analyzeFile(null, f2, sourceLocation = dir.absolutePath)

        // Apply privacy redaction (redact paths & personal filenames)
        val privacy = ForensicPrivacyOptions(
            includeGps = false,
            redactSensitivePaths = true,
            excludePersonalFilenames = true
        )
        val reports = ForensicAnalyzer.buildCaseReport(
            evidenceRecords = listOf(r1, r2),
            caseId = "CASE-UNITTEST",
            privacyOptions = privacy
        )
        assertEquals(1, reports.size)
        val report = reports.first()

        // Verify duplicate detection & non-destructive redaction
        assertTrue(report.isSanitized)
        assertEquals(1, report.duplicateGroups.size)
        assertEquals("DUP-0001", report.duplicateGroups.first().groupId)
        assertTrue(report.evidenceItems.all { it.currentFilename.startsWith("[REDACTED_FILENAME_") })
        assertTrue(report.evidenceItems.all { it.sourceLocation?.startsWith("[REDACTED_PATH]") == true })
        // Underlying files on disk must remain untouched
        assertEquals("secret_passport_scan.jpg", f1.name)
        assertTrue(f1.exists() && f2.exists())

        // Export full External AI Bundle and verify SHA-256 manifest
        val exportRoot = tempFolder.newFolder("exports")
        val bundle = ForensicReportExporter.exportReports(
            reportParts = reports,
            formats = setOf(
                ExportFormat.JSON,
                ExportFormat.MARKDOWN,
                ExportFormat.PDF,
                ExportFormat.CSV,
                ExportFormat.EXTERNAL_AI_BUNDLE
            ),
            outputRootDir = exportRoot
        )

        // Confirm all required bundle files exist and JSON parses under Schema v1.0
        val jsonFile = bundle.files.first { it.role == "json_report" }.file
        val parsedJson = JSONObject(jsonFile.readText(StandardCharsets.UTF_8))
        assertEquals("1.0", parsedJson.getString("schema_version"))
        assertEquals("CASE-UNITTEST", parsedJson.getString("case_id"))
        assertTrue(parsedJson.getJSONObject("privacy_and_redaction").getBoolean("is_sanitized"))

        // Verify SHA-256 manifest integrity check passes
        val verifyOk = ForensicReportExporter.verifyExportedBundle(bundle)
        assertTrue(verifyOk.allPassed)
        assertTrue(verifyOk.fileResults.isNotEmpty())

        // Simulate tampering with exported Markdown report and confirm verification fails
        val mdFile = bundle.files.first { it.role == "markdown_report" }.file
        mdFile.appendText("\n<!-- unauthorized modification -->")
        val verifyTampered = ForensicReportExporter.verifyExportedBundle(bundle)
        assertFalse(verifyTampered.allPassed)
        assertTrue(verifyTampered.fileResults.any { it.role == "markdown_report" && !it.passed })
    }
}
