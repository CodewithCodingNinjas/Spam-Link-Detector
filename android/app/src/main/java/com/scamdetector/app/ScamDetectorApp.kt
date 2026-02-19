package com.scamdetector.app

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build

/**
 * Application class for ScamDetector.
 * Initializes notification channels and global resources.
 */
class ScamDetectorApp : Application() {

    companion object {
        const val CHANNEL_CLIPBOARD = "clipboard_monitor"
        const val CHANNEL_SCAN_RESULT = "scan_result"
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val clipboardChannel = NotificationChannel(
                CHANNEL_CLIPBOARD,
                "Clipboard Monitor",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Notifications when a URL is detected in clipboard"
            }

            val scanResultChannel = NotificationChannel(
                CHANNEL_SCAN_RESULT,
                "Scan Results",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Notifications for URL scan results"
            }

            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(clipboardChannel)
            notificationManager.createNotificationChannel(scanResultChannel)
        }
    }
}
