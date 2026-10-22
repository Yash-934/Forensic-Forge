package com.clone.filesrecovery.forensics

import com.clone.filesrecovery.data.FileScanner
import com.clone.filesrecovery.data.RecoverySourceBadge
import com.clone.filesrecovery.data.StreamIntegrityStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

class DeepCarverArchitectureUpgradeTest {

    @Test
    fun `test 4KB sparse zero block fast skipping`() {
        val zeroBuf = ByteArray(8192)
        assertTrue(FileScanner.isSparseZeroBlock4KB(zeroBuf, 0, 8192))

        // Non-zero byte in middle 64-byte probe should prevent false skip
        zeroBuf[2048] = 0x55.toByte()
        assertFalse(FileScanner.isSparseZeroBlock4KB(zeroBuf, 0, 8192))
    }

    @Test
    fun `test JPEG carver bypasses embedded EXIF APP1 thumbnail EOI and stops after main SOS`() {
        val stream = ByteBuffer.allocate(2048)
        // Outer JPEG SOI
        stream.put(byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte(), 0xE1.toByte()))
        // APP1 segment length = 30 bytes (contains embedded thumbnail with its own SOI + SOS + EOI)
        stream.putShort(30.toShort())
        stream.put("Exif\u0000\u0000".toByteArray(Charsets.US_ASCII))
        // Embedded thumbnail SOI + SOS + EOI inside APP1
        stream.put(
            byteArrayOf(
                0xFF.toByte(), 0xD8.toByte(),
                0xFF.toByte(), 0xDA.toByte(), 0x00, 0x04, 0x01, 0x02,
                0x11, 0x22, 0x33, 0x44,
                0xFF.toByte(), 0xD9.toByte() // <-- Embedded thumbnail EOI (TRAP!)
            )
        )
        while (stream.position() < 34) {
            stream.put(0x00.toByte())
        }
        // Main JPEG SOF0 header (width = 640, height = 480)
        stream.put(
            byteArrayOf(
                0xFF.toByte(), 0xC0.toByte(),
                0x00, 0x0B,
                0x08,
                0x01, 0xE0.toByte(), // height = 480
                0x02, 0x80.toByte(), // width = 640
                0x01, 0x01, 0x11, 0x00
            )
        )
        // Main JPEG SOS (FF DA)
        stream.put(
            byteArrayOf(
                0xFF.toByte(), 0xDA.toByte(),
                0x00, 0x08,
                0x01, 0x01, 0x00, 0x00, 0x3F, 0x00
            )
        )
        // Entropy-coded scan payload
        repeat(1200) { stream.put(0x7A.toByte()) }
        // True Outer JPEG EOI (FF D9)
        val expectedEndOffset = stream.position() + 2
        stream.put(byteArrayOf(0xFF.toByte(), 0xD9.toByte()))

        val rawBytes = stream.array()
        val carvedEnd = FileScanner.findJpegEndBypassingExifThumbnail(rawBytes, 0, stream.position())
        assertEquals(expectedEndOffset, carvedEnd)
    }

    @Test
    fun `test RIFF WEBP and WAV exact Little-Endian uint32 size slicing`() {
        val declaredPayloadSize = 4096
        val buf = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN)
        buf.put("RIFF".toByteArray(Charsets.US_ASCII))
        buf.putInt(declaredPayloadSize)
        buf.put("WEBP".toByteArray(Charsets.US_ASCII))

        val totalSize = FileScanner.parseRiffContainerTotalSize(buf.array(), 0)
        assertEquals((declaredPayloadSize + 8).toLong(), totalSize)
    }

    @Test
    fun `test ZIP DOCX XLSX full EOCD tail includes 22 bytes plus comment length N`() {
        val stream = ByteBuffer.allocate(2048).order(ByteOrder.LITTLE_ENDIAN)
        // Local file header PK\x03\x04
        stream.put(byteArrayOf(0x50, 0x4B, 0x03, 0x04))
        repeat(600) { stream.put(0x41.toByte()) }

        // EOCD signature PK\x05\x06
        val eocdPos = stream.position()
        stream.put(byteArrayOf(0x50, 0x4B, 0x05, 0x06))
        // 16 bytes of EOCD fields before comment length
        repeat(16) { stream.put(0x00.toByte()) }
        // 2-byte Little-Endian comment length N = 15 at offset +20 from PK\x05\x06
        val commentLength = 15
        stream.putShort(commentLength.toShort())
        repeat(commentLength) { stream.put(0x63.toByte()) }

        val expectedEnd = eocdPos + 22 + commentLength
        val actualEnd = FileScanner.findZipEndWithFullEocd(stream.array(), 0, stream.position())
        assertNotNull(actualEnd)
        assertEquals(expectedEnd, actualEnd!!.first)
        assertEquals("zip", actualEnd.second)
    }

    @Test
    fun `test PDF carver validates xref or Root token and includes trailing newlines after EOF`() {
        val pdfWithPadding = "%PDF-1.7\n" + "X".repeat(600) + "\n<< /Root 1 0 R >>\nxref\n%%EOF\r\nTRAILING"
        val paddedBytes = pdfWithPadding.toByteArray(Charsets.ISO_8859_1)

        val endOffset = FileScanner.findValidatedPdfEnd(paddedBytes, 0, paddedBytes.size)
        val expectedOffset = pdfWithPadding.indexOf("TRAILING")
        assertEquals(expectedOffset, endOffset)

        // Fake PDF without xref or /Root must be rejected as false positive
        val fakePdf = "%PDF-1.7\n" + "Just random log text without pdf catalog tokens ".repeat(20) + "\n%%EOF\n"
        val fakeBytes = fakePdf.toByteArray(Charsets.ISO_8859_1)
        val fakeEnd = FileScanner.findValidatedPdfEnd(fakeBytes, 0, fakeBytes.size)
        assertEquals(-1, fakeEnd)
    }

    @Test
    fun `test MP4 ftyp atom chain walker flags mdat without moov as NEEDS_REPAIR_PARTIAL`() {
        val tempFile = File.createTempFile("carve_mp4_test", ".bin")
        try {
            val buf = ByteBuffer.allocate(24 * 1024).order(ByteOrder.BIG_ENDIAN)
            // Box 1: ftyp (24 bytes)
            buf.putInt(24)
            buf.put("ftyp".toByteArray(Charsets.US_ASCII))
            buf.put("isom".toByteArray(Charsets.US_ASCII))
            buf.putInt(512)
            buf.put("isommp42".toByteArray(Charsets.US_ASCII))

            // Box 2: mdat (20,000 bytes) without moov box
            buf.putInt(20000)
            buf.put("mdat".toByteArray(Charsets.US_ASCII))
            repeat(20000 - 8) { buf.put(0x33.toByte()) }

            tempFile.writeBytes(buf.array().copyOf(buf.position()))

            RandomAccessFile(tempFile, "r").use { raf ->
                val walkResult = FileScanner.walkIsoBmffAtomChain(raf, 0L, raf.length())
                assertNotNull(walkResult)
                assertEquals(20024L, walkResult!!.first)
                assertEquals(StreamIntegrityStatus.NEEDS_REPAIR_PARTIAL, walkResult.second)
            }
        } finally {
            tempFile.delete()
        }
    }

    @Test
    fun `test fast active gallery fingerprint deduplication`() {
        val tempActive = File.createTempFile("active_gallery_photo", ".jpg")
        val tempClone = File.createTempFile("carved_clone_photo", ".jpg")
        try {
            val content = ByteArray(12_000) { idx -> ((idx * 31 + 7) and 0xFF).toByte() }
            tempActive.writeBytes(content)
            tempClone.writeBytes(content)

            val fp1 = FileScanner.computeFastFingerprint(tempActive)
            val fp2 = FileScanner.computeFastFingerprint(tempClone)
            assertNotNull(fp1)
            assertEquals(fp1, fp2)

            val index = FileScanner.ActiveGalleryFingerprintIndex()
            index.registerActiveFile(tempActive, mediaId = 101L)
            assertTrue(index.matchesActiveGallery(tempClone))
            assertEquals("UNOVERWRITTEN_SECTOR", RecoverySourceBadge.UNOVERWRITTEN_SECTOR.displayBadge)
        } finally {
            tempActive.delete()
            tempClone.delete()
        }
    }
}
