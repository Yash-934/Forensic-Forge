package com.clone.filesrecovery.data

import android.content.ContentProviderOperation
import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.ContactsContract
import android.provider.MediaStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/** Contacts list + VCF backup / restore (the original app's Contacts Backup feature). */
object ContactsHelper {

    suspend fun loadContacts(context: Context): List<ContactInfo> = withContext(Dispatchers.IO) {
        val result = LinkedHashMap<String, ContactInfo>()
        val resolver = context.contentResolver
        resolver.query(
            ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
            arrayOf(
                ContactsContract.CommonDataKinds.Phone.CONTACT_ID,
                ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME,
                ContactsContract.CommonDataKinds.Phone.NUMBER
            ),
            null, null,
            ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME + " ASC"
        )?.use { c ->
            while (c.moveToNext()) {
                val id = c.getString(0) ?: continue
                val name = c.getString(1) ?: "Unknown"
                val number = c.getString(2) ?: continue
                val existing = result[id]
                result[id] = ContactInfo(
                    id = id,
                    name = name,
                    phones = (existing?.phones ?: emptyList()) + number,
                    emails = existing?.emails ?: emptyList()
                )
            }
        }
        // Contacts that have no phone number still show up (name + email only).
        resolver.query(
            ContactsContract.Contacts.CONTENT_URI,
            arrayOf(ContactsContract.Contacts._ID, ContactsContract.Contacts.DISPLAY_NAME),
            null, null, null
        )?.use { c ->
            while (c.moveToNext()) {
                val id = c.getString(0) ?: continue
                if (!result.containsKey(id)) {
                    result[id] = ContactInfo(id, c.getString(1) ?: "Unknown", emptyList(), emptyList())
                }
            }
        }
        result.values.sortedBy { it.name.lowercase() }
    }

    fun toVcf(contacts: List<ContactInfo>): String = buildString {
        contacts.forEach { c ->
            append("BEGIN:VCARD\r\nVERSION:3.0\r\n")
            append("FN:").append(c.name.replace("\n", " ")).append("\r\n")
            c.phones.forEach { append("TEL;TYPE=CELL:").append(it).append("\r\n") }
            c.emails.forEach { append("EMAIL:").append(it).append("\r\n") }
            append("END:VCARD\r\n")
        }
    }

    /** Save a .vcf backup into Downloads/ContactsBackup. Returns a display path or null. */
    suspend fun backupToDownloads(context: Context, contacts: List<ContactInfo>): String? =
        withContext(Dispatchers.IO) {
            val vcf = toVcf(contacts)
            val fileName = "contacts_backup_${System.currentTimeMillis()}.vcf"
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val resolver = context.contentResolver
                val collection = MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)
                val values = ContentValues().apply {
                    put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
                    put(MediaStore.MediaColumns.MIME_TYPE, "text/x-vcard")
                    put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/ContactsBackup")
                }
                runCatching {
                    val uri = resolver.insert(collection, values) ?: return@runCatching null
                    resolver.openOutputStream(uri)?.use { it.write(vcf.toByteArray()) }
                    "Download/ContactsBackup/$fileName"
                }.getOrNull()
            } else {
                @Suppress("DEPRECATION")
                val dir = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "ContactsBackup").apply { mkdirs() }
                runCatching { File(dir, fileName).writeText(vcf); dir.absolutePath + "/" + fileName }.getOrNull()
            }
        }

    /** Parse a simple VCF (FN / TEL / EMAIL) and insert contacts. Returns inserted count. */
    suspend fun importVcf(context: Context, uri: Uri): Int = withContext(Dispatchers.IO) {
        val text = runCatching {
            context.contentResolver.openInputStream(uri)?.bufferedReader()?.readText()
        }.getOrNull() ?: return@withContext 0
        val ops = ArrayList<ContentProviderOperation>()
        var insertedCount = 0
        var name: String? = null
        val phones = ArrayList<String>()
        val emails = ArrayList<String>()
        fun flush() {
            val n = name ?: return
            insertedCount++
            val rawIndex = ops.size
            ops.add(
                ContentProviderOperation.newInsert(ContactsContract.RawContacts.CONTENT_URI)
                    .withValue(ContactsContract.RawContacts.ACCOUNT_TYPE, null)
                    .withValue(ContactsContract.RawContacts.ACCOUNT_NAME, null)
                    .build()
            )
            ops.add(
                ContentProviderOperation.newInsert(ContactsContract.Data.CONTENT_URI)
                    .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, rawIndex)
                    .withValue(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.StructuredName.CONTENT_ITEM_TYPE)
                    .withValue(ContactsContract.CommonDataKinds.StructuredName.DISPLAY_NAME, n)
                    .build()
            )
            phones.forEach { p ->
                ops.add(
                    ContentProviderOperation.newInsert(ContactsContract.Data.CONTENT_URI)
                        .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, rawIndex)
                        .withValue(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.Phone.CONTENT_ITEM_TYPE)
                        .withValue(ContactsContract.CommonDataKinds.Phone.NUMBER, p)
                        .withValue(ContactsContract.CommonDataKinds.Phone.TYPE, ContactsContract.CommonDataKinds.Phone.TYPE_MOBILE)
                        .build()
                )
            }
            emails.forEach { e ->
                ops.add(
                    ContentProviderOperation.newInsert(ContactsContract.Data.CONTENT_URI)
                        .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, rawIndex)
                        .withValue(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.Email.CONTENT_ITEM_TYPE)
                        .withValue(ContactsContract.CommonDataKinds.Email.ADDRESS, e)
                        .build()
                )
            }
            name = null; phones.clear(); emails.clear()
        }
        text.lineSequence().forEach { raw ->
            val line = raw.trim()
            when {
                line.startsWith("BEGIN:VCARD", true) -> { name = null; phones.clear(); emails.clear() }
                line.startsWith("FN:", true) -> name = line.substringAfter(':').trim()
                line.startsWith("TEL", true) -> phones += line.substringAfterLast(':').trim()
                line.startsWith("EMAIL", true) -> emails += line.substringAfterLast(':').trim()
                line.startsWith("END:VCARD", true) -> flush()
            }
        }
        if (ops.isEmpty()) return@withContext 0
        val applied = runCatching { context.contentResolver.applyBatch(ContactsContract.AUTHORITY, ops) }.isSuccess
        if (applied) insertedCount else 0
    }
}
