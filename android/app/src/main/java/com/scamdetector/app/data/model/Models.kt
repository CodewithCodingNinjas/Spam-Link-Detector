package com.scamdetector.app.data.model

import com.google.gson.annotations.SerializedName

/**
 * Request model for URL scanning.
 */
data class URLCheckRequest(
    @SerializedName("url") val url: String,
    @SerializedName("device_id") val deviceId: String? = null
)

/**
 * Full threat report response from API.
 */
data class ThreatReport(
    @SerializedName("url") val url: String,
    @SerializedName("risk_score") val riskScore: Double,
    @SerializedName("status") val status: String,
    @SerializedName("confidence") val confidence: Double,
    @SerializedName("ml_prediction") val mlPrediction: String,
    @SerializedName("ml_confidence") val mlConfidence: Double,
    @SerializedName("domain_age_days") val domainAgeDays: Int?,
    @SerializedName("ssl_valid") val sslValid: Boolean?,
    @SerializedName("ssl_issuer") val sslIssuer: String?,
    @SerializedName("ssl_expiry") val sslExpiry: String?,
    @SerializedName("impersonation_risk") val impersonationRisk: Boolean,
    @SerializedName("impersonation_target") val impersonationTarget: String?,
    @SerializedName("suspicious_keywords") val suspiciousKeywords: List<String>,
    @SerializedName("url_features") val urlFeatures: URLFeatures?,
    @SerializedName("google_safe_browsing") val googleSafeBrowsing: String?,
    @SerializedName("recommendations") val recommendations: List<String>,
    @SerializedName("scanned_at") val scannedAt: String
)

/**
 * URL structural features.
 */
data class URLFeatures(
    @SerializedName("url_length") val urlLength: Int,
    @SerializedName("has_https") val hasHttps: Boolean,
    @SerializedName("has_ip_address") val hasIpAddress: Boolean,
    @SerializedName("num_subdomains") val numSubdomains: Int,
    @SerializedName("is_suspicious_tld") val isSuspiciousTld: Boolean,
    @SerializedName("is_shortened") val isShortened: Boolean,
    @SerializedName("suspicious_keyword_count") val suspiciousKeywordCount: Int
)

/**
 * Scan history response.
 */
data class ScanHistoryResponse(
    @SerializedName("total") val total: Int,
    @SerializedName("records") val records: List<ScanHistoryItem>
)

/**
 * Single scan history item from API.
 */
data class ScanHistoryItem(
    @SerializedName("id") val id: Int,
    @SerializedName("url") val url: String,
    @SerializedName("risk_score") val riskScore: Double,
    @SerializedName("status") val status: String,
    @SerializedName("scanned_at") val scannedAt: String
)

/**
 * Health check response.
 */
data class HealthResponse(
    @SerializedName("status") val status: String,
    @SerializedName("version") val version: String,
    @SerializedName("ml_model_loaded") val mlModelLoaded: Boolean
)
