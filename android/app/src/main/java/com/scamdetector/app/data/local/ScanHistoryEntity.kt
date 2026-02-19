package com.scamdetector.app.data.local

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Room entity for storing scan history locally.
 */
@Entity(tableName = "scan_history")
data class ScanHistoryEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val url: String,
    val riskScore: Double,
    val status: String,
    val mlPrediction: String?,
    val mlConfidence: Double?,
    val domainAgeDays: Int?,
    val sslValid: Boolean?,
    val impersonationRisk: Boolean = false,
    val impersonationTarget: String?,
    val suspiciousKeywords: String?,  // JSON string of keywords list
    val confidence: Double?,
    val recommendations: String?,  // JSON string of recommendations list
    val scannedAt: Long = System.currentTimeMillis(),
    val responseJson: String?  // Full JSON response for detail view
)
