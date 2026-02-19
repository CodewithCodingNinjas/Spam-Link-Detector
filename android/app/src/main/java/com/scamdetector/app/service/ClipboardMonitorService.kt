package com.scamdetector.app.service

import android.app.*
import android.content.*
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.scamdetector.app.R
import com.scamdetector.app.ScamDetectorApp
import com.scamdetector.app.ui.MainActivity

/**
 * Foreground service that monitors clipboard for URLs.
 * When a URL is detected, shows a notification to scan it.
 */
class ClipboardMonitorService : Service() {

    private var clipboardManager: ClipboardManager? = null
    private var clipListener: ClipboardManager.OnPrimaryClipChangedListener? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        startForegroundService()
        setupClipboardMonitor()
    }

    private fun startForegroundService() {
        val notification = NotificationCompat.Builder(this, ScamDetectorApp.CHANNEL_CLIPBOARD)
            .setContentTitle("Scam Link Detector")
            .setContentText("Monitoring clipboard for suspicious links...")
            .setSmallIcon(R.drawable.ic_shield)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .build()

        startForeground(1, notification)
    }

    private fun setupClipboardMonitor() {
        clipboardManager = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        clipListener = ClipboardManager.OnPrimaryClipChangedListener {
            val clip = clipboardManager?.primaryClip
            if (clip != null && clip.itemCount > 0) {
                val text = clip.getItemAt(0).text?.toString() ?: return@OnPrimaryClipChangedListener
                val url = extractUrl(text)
                if (url != null) {
                    showScanNotification(url)
                }
            }
        }
        clipboardManager?.addPrimaryClipChangedListener(clipListener)
    }

    private fun extractUrl(text: String): String? {
        val urlPattern = Regex(
            """https?://[^\s<>"{}|\\^`\[\]]+""",
            RegexOption.IGNORE_CASE
        )
        return urlPattern.find(text)?.value
    }

    private fun showScanNotification(url: String) {
        val intent = Intent(this, MainActivity::class.java).apply {
            action = Intent.ACTION_SEND
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, url)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }

        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, ScamDetectorApp.CHANNEL_CLIPBOARD)
            .setContentTitle("🔗 New Link Detected")
            .setContentText("Scan now? $url")
            .setSmallIcon(R.drawable.ic_shield)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .addAction(
                R.drawable.ic_scan, "Scan Now", pendingIntent
            )
            .build()

        val notificationManager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.notify(System.currentTimeMillis().toInt(), notification)
    }

    override fun onDestroy() {
        clipListener?.let {
            clipboardManager?.removePrimaryClipChangedListener(it)
        }
        super.onDestroy()
    }
}
