package com.clone.filesrecovery.service

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import com.clone.filesrecovery.data.AppStore
import com.clone.filesrecovery.data.SavedNotification

/**
 * Records the text of every incoming notification.
 * If a sender later deletes/edits a message (WhatsApp "delete for everyone" etc.),
 * the original notification text is still here — this is the original app's
 * "Notification Recovery" feature.
 */
class NotificationRecorderService : NotificationListenerService() {

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        val n = sbn ?: return
        if (n.packageName == packageName) return
        val extras = n.notification.extras
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty()
        val text = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()
            ?: extras.getCharSequence(Notification.EXTRA_TEXT)?.toString().orEmpty()
        if (title.isBlank() && text.isBlank()) return
        val appLabel = runCatching {
            val pm = packageManager
            pm.getApplicationLabel(pm.getApplicationInfo(n.packageName, 0)).toString()
        }.getOrDefault(n.packageName)
        val isMedia = n.notification.category == Notification.CATEGORY_TRANSPORT ||
            (n.notification.flags and Notification.FLAG_FOREGROUND_SERVICE) != 0 && title.isNotBlank()
        AppStore.addNotification(
            applicationContext,
            SavedNotification(
                id = System.currentTimeMillis(),
                packageName = n.packageName,
                appLabel = appLabel,
                title = title,
                text = text,
                time = n.postTime,
                isMedia = isMedia
            )
        )
    }
}
