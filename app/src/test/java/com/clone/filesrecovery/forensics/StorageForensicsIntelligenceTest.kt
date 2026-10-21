package com.clone.filesrecovery.forensics

import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.nio.charset.StandardCharsets
import java.util.Random

class StorageForensicsIntelligenceTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun `never calculates encrypted data as total storage minus visible files and separates whole-device scope`() = runBlocking {
        val root = tempFolder.newFolder("storage_scope_test")
        val normalDoc = File(root, "readme.txt").apply {
            writeText("Deterministic storage forensics verification text payload.\n".repeat(10))
        }

        // Simulate a 64 GB device with 24 GB free (40 GB used by OS + sandboxed apps)
        val totalCapacity = 64L * 1024 * 1024 * 1024
        val freeCapacity = 24L * 1024 * 1024 * 1024

        val report = StorageForensicsAnalyzer.analyzeStorage(
            context = null,
            explicitRoots = listOf(root),
            totalDeviceCapacityOverride = totalCapacity to freeCapacity
        )

        assertEquals(totalCapacity, report.totalDeviceBytes)
        assertEquals(freeCapacity, report.availableDeviceBytes)
        assertEquals(totalCapacity - freeCapacity, report.usedDeviceBytes)
        assertEquals(normalDoc.length(), report.bytesActuallyScanned)
        assertEquals(1, report.filesActuallyScanned)

        // Critical: uninspected OS/sandboxed bytes (~40 GB) must NEVER be counted as encrypted files
        assertEquals(0, report.totalConfirmedEncryptedFiles)
        assertEquals(0L, report.totalConfirmedEncryptedBytes)
        assertEquals(0, report.totalPotentialEncryptedFiles)
        assertEquals(0L, report.totalPotentialEncryptedBytes)
        assertTrue(report.uninspectedSystemAndSandboxedBytes > 39L * 1024 * 1024 * 1024)
        assertTrue(report.coverageCalculationMethod.contains("Accessible Coverage (%)"))
        assertTrue(report.scopeDistinctionExplanation.contains("NEVER assumed or calculated to be encrypted"))
    }

    @Test
    fun `detects confirmed encryption headers, high-entropy indicators, and excludes compressed media`() = runBlocking {
        val root = tempFolder.newFolder("encryption_forensics_test")

        // 1. Confirmed Encrypted ZIP (50 4B 03 04 with general purpose bit 0 = 0x0001 at offset 6)
        val encZip = File(root, "secret_archive.zip")
        val zipHeader = byteArrayOf(
            0x50, 0x4B, 0x03, 0x04, // PK\x03\x04
            0x14, 0x00,             // version needed = 20
            0x01, 0x00,             // general purpose bit flag = 0x0001 (Encrypted!)
            0x08, 0x00,             // compression = deflate
            0x00, 0x00, 0x00, 0x00,
            0x12, 0x34, 0x56, 0x78
        ) + ByteArray(512) { (it * 31).toByte() }
        encZip.writeBytes(zipHeader)

        // 2. Confirmed Encrypted PDF (%PDF-1.7 with /Encrypt dictionary)
        val encPdf = File(root, "confidential.pdf")
        encPdf.writeBytes(
            ("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R /Encrypt 2 0 R >>\n%%EOF")
                .toByteArray(StandardCharsets.US_ASCII)
        )

        // 3. Confirmed OpenSSL Salted__ ciphertext
        val opensslFile = File(root, "backup.bin")
        val saltedHeader = "Salted__12345678".toByteArray(StandardCharsets.US_ASCII) + ByteArray(256) { (it xor 0x5A).toByte() }
        opensslFile.writeBytes(saltedHeader)

        // 4. Potential Encryption / High-Entropy Unknown Blob (deterministic PRNG covering all 256 byte values)
        val highEntropyBlob = File(root, "mystery_payload.dat")
        val rng = Random(424242L)
        val randomBytes = ByteArray(16 * 1024)
        rng.nextBytes(randomBytes)
        // Ensure first 8 bytes do not accidentally match any known magic signature
        randomBytes[0] = 0x13
        randomBytes[1] = 0x37
        randomBytes[2] = 0x42
        randomBytes[3] = 0x99.toByte()
        highEntropyBlob.writeBytes(randomBytes)

        // 5. Standard Compressed JPEG with high-entropy body (should be excluded as COMPRESSED_MEDIA_NOT_ENCRYPTED)
        val normalJpeg = File(root, "camera_photo.jpg")
        val jpegBytes = byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte(), 0xE0.toByte()) +
            randomBytes.copyOfRange(0, 8192) +
            byteArrayOf(0xFF.toByte(), 0xD9.toByte())
        normalJpeg.writeBytes(jpegBytes)

        val report = StorageForensicsAnalyzer.analyzeStorage(
            context = null,
            explicitRoots = listOf(root)
        )

        // Verify 3 confirmed encrypted files (ZIP, PDF, OpenSSL)
        assertEquals(3, report.totalConfirmedEncryptedFiles)
        val confirmedNames = report.confirmedEncryptionFindings.map { it.name }.toSet()
        assertTrue(confirmedNames.contains("secret_archive.zip"))
        assertTrue(confirmedNames.contains("confidential.pdf"))
        assertTrue(confirmedNames.contains("backup.bin"))

        // Verify 1 potential high-entropy indicator (mystery_payload.dat)
        assertEquals(1, report.totalPotentialEncryptedFiles)
        val pot = report.potentialEncryptionFindings.first()
        assertEquals("mystery_payload.dat", pot.name)
        assertTrue(pot.shannonEntropyBitsPerByte >= 7.80)

        // Verify JPEG was recognized as compressed media and NOT flagged as encrypted
        assertFalse(confirmedNames.contains("camera_photo.jpg"))
        assertFalse(report.potentialEncryptionFindings.any { it.name == "camera_photo.jpg" })
        assertTrue(report.compressedMediaHighEntropyCount >= 1)
    }

    @Test
    fun `detects nomedia markers, dot-prefixed directories, trash files, compound extensions, and signature mismatches`() = runBlocking {
        val root = tempFolder.newFolder("hidden_and_mismatch_test")

        // 1. Hidden directory with .nomedia
        val hiddenVaultDir = File(root, ".private_gallery").apply { mkdirs() }
        File(hiddenVaultDir, ".nomedia").writeBytes(ByteArray(0))

        // 2. Trashed photo
        val trashedFile = File(root, ".trashed-1700000000-IMG_01.jpg")
        trashedFile.writeBytes(byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte(), 0xE0.toByte(), 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0xFF.toByte(), 0xD9.toByte()))

        // 3. Compound extension file with PDF header disguised as .jpg
        val disguisedPdf = File(root, "statement.pdf.jpg")
        disguisedPdf.writeBytes("%PDF-1.5\n1 0 obj\n<<>>\nendobj\n%%EOF".toByteArray(StandardCharsets.US_ASCII))

        val report = StorageForensicsAnalyzer.analyzeStorage(
            context = null,
            explicitRoots = listOf(root)
        )

        assertEquals(1, report.nomediaFilesCount)
        assertTrue(report.dotDirectoriesCount >= 1)
        assertTrue(report.trashedOrRecycleCount >= 1)

        val nomediaFinding = report.hiddenFindings.firstOrNull { it.isNoMediaMarker }
        assertNotNull(nomediaFinding)
        assertEquals(HiddenArtifactCategory.MEDIA_INDEXING_CONTROL_NOMEDIA, nomediaFinding!!.category)
        assertTrue(nomediaFinding.mediaIndexingEffect!!.contains("Suppresses Android MediaStore indexing"))

        // Verify signature mismatch (statement.pdf.jpg has .jpg extension but %PDF magic header)
        assertEquals(1, report.totalSignatureMismatches)
        val mismatch = report.signatureMismatches.first()
        assertEquals("statement.pdf.jpg", mismatch.name)
        assertEquals("jpg", mismatch.declaredExtension)
        assertEquals("PDF", mismatch.detectedFormat)

        // Verify JSON & Markdown export integrity
        val exportDir = tempFolder.newFolder("export_out")
        val exported = StorageForensicsAnalyzer.exportReportFiles(report, exportDir)
        assertTrue(exported.jsonFile.exists())
        assertTrue(exported.markdownFile.exists())
        assertEquals(64, exported.jsonSha256.length)
        assertEquals(64, exported.markdownSha256.length)

        val parsedJson = JSONObject(exported.jsonFile.readText())
        assertEquals("deepvault.storage_forensics_intelligence.v1", parsedJson.getString("schema"))
        assertEquals(report.reportId, parsedJson.getString("report_id"))
    }
}
