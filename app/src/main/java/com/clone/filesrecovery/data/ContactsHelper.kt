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

/**
 * Contacts Recovery + VCF Backup & Restore engine.
 * Discovers:
 *  1. Active device contacts
 *  2. Soft-deleted RawContacts (RawContacts.DELETED = 1 before sync purge)
 *  3. Contacts inside .vcf files found across shared storage
 */
object ContactsHelper {

    suspend fun loadContacts(context: Context): List<ContactInfo> = withContext(Dispatchers.IO) {
        val result = LinkedHashMap<String, ContactInfo>()
        val resolver = context.contentResolver

        // 1. Active phone contacts
        runCatching {
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
                        phones = ((existing?.phones ?: emptyList()) + number).distinct(),
                        emails = existing?.emails ?: emptyList(),
                        isDeletedOrBackup = false,
                        sourceLabel = "Device"
                    )
                }
            }
        }

        // 2. Soft-deleted RawContacts (DELETED = 1)
        runCatching {
            resolver.query(
                ContactsContract.RawContacts.CONTENT_URI,
                arrayOf(
                    ContactsContract.RawContacts._ID,
                    ContactsContract.RawContacts.DISPLAY_NAME_PRIMARY,
                    ContactsContract.RawContacts.DELETED
                ),
                "${ContactsContract.RawContacts.DELETED} = 1",
                null,
                null
            )?.use { c ->
                while (c.moveToNext()) {
                    val rawId = c.getString(0) ?: continue
                    val name = c.getString(1) ?: "Deleted Contact"
                    val key = "del_$rawId"
                    result[key] = ContactInfo(
                        id = key,
                        name = name,
                        phones = emptyList(),
                        emails = emptyList(),
                        isDeletedOrBackup = true,
                        sourceLabel = "Deleted RawContact"
                    )
                }
            }
        }

        // 3. Scan .vcf files on storage for recoverable contacts
        runCatching {
            val root = Environment.getExternalStorageDirectory()
            if (root != null && root.exists() && root.canRead()) {
                root.walkTopDown().maxDepth(8).forEach { f ->
                    if (f.isFile && f.extension.equals("vcf", ignoreCase = true) && f.length() in 10..5_000_000) {
                        parseVcfText(f.readText(), f.name).forEach { vcfContact ->
                            val k = "vcf_${vcfContact.name}_${vcfContact.phones.firstOrNull().orEmpty()}"
                            if (!result.containsKey(k)) {
                                result[k] = vcfContact.copy(id = k)
                            }
                        }
                    }
                }
            }
        }

        result.values.sortedWith(
            compareByDescending<ContactInfo> { it.isDeletedOrBackup }
                .thenBy { it.name.lowercase() }
        )
    }

    private fun parseVcfText(text: String, fileName: String): List<ContactInfo> {
        val list = ArrayList<ContactInfo>()
        var name: String? = null
        val phones = ArrayList<String>()
        val emails = ArrayList<String>()
        text.lineSequence().forEach { raw ->
            val line = raw.trim()
            when {
                line.startsWith("BEGIN:VCARD", true) -> {
                    name = null; phones.clear(); emails.clear()
                }
                line.startsWith("FN:", true) -> name = line.substringAfter(':').trim()
                line.startsWith("TEL", true) -> phones += line.substringAfterLast(':').trim()
                line.startsWith("EMAIL", true) -> emails += line.substringAfterLast(':').trim()
                line.startsWith("END:VCARD", true) -> {
                    val n = name
                    if (!n.isNullOrBlank()) {
                        list += ContactInfo(
                            id = "vcf_${list.size}",
                            name = n,
                            phones = phones.toList(),
                            emails = emails.toList(),
                            isDeletedOrBackup = true,
                            sourceLabel = "Backup ($fileName)"
                        )
                    }
                }
            }
        }
        return list
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
                val dir = File(
                    Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
                    "ContactsBackup"
                ).apply { mkdirs() }
                runCatching {
                    File(dir, fileName).writeText(vcf)
                    dir.absolutePath + "/" + fileName
                }.getOrNull()
            }
        }

    suspend fun restoreContact(context: Context, contact: ContactInfo): Boolean = withContext(Dispatchers.IO) {
        val ops = ArrayList<ContentProviderOperation>()
        ops.add(
            ContentProviderOperation.newInsert(ContactsContract.RawContacts.CONTENT_URI)
                .withValue(ContactsContract.RawContacts.ACCOUNT_TYPE, null)
                .withValue(ContactsContract.RawContacts.ACCOUNT_NAME, null)
                .build()
        )
        ops.add(
            ContentProviderOperation.newInsert(ContactsContract.Data.CONTENT_URI)
                .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, 0)
                .withValue(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.StructuredName.CONTENT_ITEM_TYPE)
                .withValue(ContactsContract.CommonDataKinds.StructuredName.DISPLAY_NAME, contact.name)
                .build()
        )
        contact.phones.forEach { p ->
            ops.add(
                ContentProviderOperation.newInsert(ContactsContract.Data.CONTENT_URI)
                    .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, 0)
                    .withValue(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.Phone.CONTENT_ITEM_TYPE)
                    .withValue(ContactsContract.CommonDataKinds.Phone.NUMBER, p)
                    .withValue(ContactsContract.CommonDataKinds.Phone.TYPE, ContactsContract.CommonDataKinds.Phone.TYPE_MOBILE)
                    .build()
            )
        }
        contact.emails.forEach { e ->
            ops.add(
                ContentProviderOperation.newInsert(ContactsContract.Data.CONTENT_URI)
                    .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, 0)
                    .withValue(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.Email.CONTENT_ITEM_TYPE)
                    .withValue(ContactsContract.CommonDataKinds.Email.ADDRESS, e)
                    .build()
            )
        }
        runCatching { context.contentResolver.applyBatch(ContactsContract.AUTHORITY, ops) }.isSuccess
    }

    suspend fun importVcf(context: Context, uri: Uri): Int = withContext(Dispatchers.IO) {
        val text = runCatching {
            context.contentResolver.openInputStream(uri)?.bufferedReader()?.readText()
        }.getOrNull() ?: return@withContext 0
        val parsed = parseVcfText(text, "Imported")
        var count = 0
        for (c in parsed) {
            if (restoreContact(context, c)) count++
        }
        count
    }
}
