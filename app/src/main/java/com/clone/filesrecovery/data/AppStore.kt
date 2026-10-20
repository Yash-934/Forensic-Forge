package com.clone.filesrecovery.data

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Tiny JSON-file store (the original app uses a Room database;
 * a JSON store keeps this clone dependency-light with the same behaviour):
 *  - recovered-file history
 *  - notifications recorded by the NotificationListenerService
 */
object AppStore {

    private fun file(context: Context, name: String) = File(context.filesDir, name)

    // ---------- Recovered history ----------

    @Synchronized
    fun loadRecovered(context: Context): List<RecoveredRecord> {
        val f = file(context, "recovered.json")
        if (!f.exists()) return emptyList()
        return runCatching {
            val arr = JSONArray(f.readText())
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                RecoveredRecord(
                    originalPath = o.getString("originalPath"),
                    recoveredPath = o.getString("recoveredPath"),
                    name = o.getString("name"),
                    category = runCatching { FileCategory.valueOf(o.getString("category")) }.getOrDefault(FileCategory.DOCUMENT),
                    size = o.getLong("size"),
                    recoveredAt = o.getLong("recoveredAt")
                )
            }.sortedByDescending { it.recoveredAt }
        }.getOrDefault(emptyList())
    }

    @Synchronized
    fun addRecovered(context: Context, records: List<RecoveredRecord>) {
        val all = loadRecovered(context) + records
        val arr = JSONArray()
        all.forEach { r ->
            arr.put(JSONObject().apply {
                put("originalPath", r.originalPath)
                put("recoveredPath", r.recoveredPath)
                put("name", r.name)
                put("category", r.category.name)
                put("size", r.size)
                put("recoveredAt", r.recoveredAt)
            })
        }
        file(context, "recovered.json").writeText(arr.toString())
    }

    // ---------- Recorded notifications ----------

    private const val MAX_NOTIFICATIONS = 500

    @Synchronized
    fun loadNotifications(context: Context): List<SavedNotification> {
        val f = file(context, "notifications.json")
        if (!f.exists()) return emptyList()
        return runCatching {
            val arr = JSONArray(f.readText())
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                SavedNotification(
                    id = o.getLong("id"),
                    packageName = o.getString("packageName"),
                    appLabel = o.optString("appLabel"),
                    title = o.optString("title"),
                    text = o.optString("text"),
                    time = o.getLong("time"),
                    isMedia = o.optBoolean("isMedia")
                )
            }.sortedByDescending { it.time }
        }.getOrDefault(emptyList())
    }

    @Synchronized
    fun addNotification(context: Context, n: SavedNotification) {
        val all = (listOf(n) + loadNotifications(context)).take(MAX_NOTIFICATIONS)
        writeNotifications(context, all)
    }

    @Synchronized
    fun clearNotifications(context: Context) = writeNotifications(context, emptyList())

    private fun writeNotifications(context: Context, list: List<SavedNotification>) {
        val arr = JSONArray()
        list.forEach { n ->
            arr.put(JSONObject().apply {
                put("id", n.id)
                put("packageName", n.packageName)
                put("appLabel", n.appLabel)
                put("title", n.title)
                put("text", n.text)
                put("time", n.time)
                put("isMedia", n.isMedia)
            })
        }
        file(context, "notifications.json").writeText(arr.toString())
    }
}
