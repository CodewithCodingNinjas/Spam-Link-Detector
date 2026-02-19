package com.scamdetector.app.ui

import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.scamdetector.app.R
import com.scamdetector.app.data.local.AppDatabase
import com.scamdetector.app.data.model.ThreatReport
import com.scamdetector.app.databinding.ActivityScanDetailBinding
import kotlinx.coroutines.*

/**
 * Detailed threat report screen.
 * Shows comprehensive analysis results.
 */
class ScanDetailActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_SCAN_ID = "extra_scan_id"
        const val EXTRA_REPORT_JSON = "extra_report_json"
    }

    private lateinit var binding: ActivityScanDetailBinding
    private val gson = Gson()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityScanDetailBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Back button
        binding.toolbar.setNavigationOnClickListener { finish() }

        // Load report
        val reportJson = intent.getStringExtra(EXTRA_REPORT_JSON)
        val scanId = intent.getLongExtra(EXTRA_SCAN_ID, -1)

        if (reportJson != null) {
            val report = gson.fromJson(reportJson, ThreatReport::class.java)
            displayReport(report)
        } else if (scanId != -1L) {
            loadFromDatabase(scanId)
        } else {
            finish()
        }
    }

    private fun loadFromDatabase(scanId: Long) {
        CoroutineScope(Dispatchers.IO).launch {
            val dao = AppDatabase.getInstance(this@ScanDetailActivity).scanHistoryDao()
            val entity = dao.getScanById(scanId)
            entity?.responseJson?.let { json ->
                val report = gson.fromJson(json, ThreatReport::class.java)
                withContext(Dispatchers.Main) {
                    displayReport(report)
                }
            } ?: withContext(Dispatchers.Main) { finish() }
        }
    }

    private fun displayReport(report: ThreatReport) {
        // URL
        binding.tvUrl.text = report.url

        // Risk Score
        binding.tvRiskScore.text = report.riskScore.toInt().toString()
        binding.circularProgress.progress = report.riskScore.toInt()

        // Status
        binding.tvStatus.text = report.status
        val statusColor = when (report.status) {
            "Safe" -> R.color.safe_green
            "Suspicious" -> R.color.suspicious_yellow
            "Phishing" -> R.color.phishing_red
            else -> R.color.suspicious_yellow
        }
        val color = ContextCompat.getColor(this, statusColor)
        binding.tvStatus.setTextColor(color)
        binding.circularProgress.setIndicatorColor(color)
        binding.cardRiskScore.setStrokeColor(color)

        // Confidence
        binding.tvConfidence.text = "Confidence: ${report.confidence}%"

        // ML Prediction
        binding.tvMlPrediction.text = report.mlPrediction
        binding.tvMlConfidence.text = "${report.mlConfidence}%"
        binding.progressMl.progress = report.mlConfidence.toInt()

        // Domain Age
        binding.tvDomainAge.text = report.domainAgeDays?.let {
            "$it days"
        } ?: "Unable to determine"
        binding.ivDomainAge.setImageResource(
            if ((report.domainAgeDays ?: 365) < 90) R.drawable.ic_warning else R.drawable.ic_check
        )

        // SSL Status
        binding.tvSslStatus.text = when (report.sslValid) {
            true -> "Valid SSL Certificate"
            false -> "Invalid / Missing SSL"
            null -> "Unable to check"
        }
        binding.tvSslIssuer.text = "Issuer: ${report.sslIssuer ?: "N/A"}"
        binding.tvSslExpiry.text = "Expires: ${report.sslExpiry ?: "N/A"}"
        binding.ivSslStatus.setImageResource(
            if (report.sslValid == true) R.drawable.ic_check else R.drawable.ic_warning
        )

        // Brand Impersonation
        if (report.impersonationRisk) {
            binding.cardImpersonation.visibility = View.VISIBLE
            binding.tvImpersonationTarget.text =
                "Possible impersonation of: ${report.impersonationTarget ?: "Unknown Brand"}"
            binding.ivImpersonation.setImageResource(R.drawable.ic_warning)
        } else {
            binding.cardImpersonation.visibility = View.VISIBLE
            binding.tvImpersonationTarget.text = "No brand impersonation detected"
            binding.ivImpersonation.setImageResource(R.drawable.ic_check)
        }

        // Suspicious Keywords
        if (report.suspiciousKeywords.isNotEmpty()) {
            binding.tvKeywords.text = report.suspiciousKeywords.joinToString(", ")
            binding.chipGroupKeywords.visibility = View.VISIBLE
        } else {
            binding.tvKeywords.text = "No suspicious keywords found"
            binding.chipGroupKeywords.visibility = View.GONE
        }

        // URL Features
        report.urlFeatures?.let { features ->
            binding.tvUrlLength.text = "URL Length: ${features.urlLength}"
            binding.tvHttps.text = "HTTPS: ${if (features.hasHttps) "Yes" else "No"}"
            binding.tvIpAddress.text = "IP in URL: ${if (features.hasIpAddress) "Yes" else "No"}"
            binding.tvSubdomains.text = "Subdomains: ${features.numSubdomains}"
            binding.tvSuspiciousTld.text = "Suspicious TLD: ${if (features.isSuspiciousTld) "Yes" else "No"}"
            binding.tvShortened.text = "Shortened URL: ${if (features.isShortened) "Yes" else "No"}"
        }

        // Google Safe Browsing
        binding.tvSafeBrowsing.text = when (report.googleSafeBrowsing) {
            "safe" -> "No threats found"
            "threat_found" -> "⚠️ Threat detected!"
            "api_not_configured" -> "Not configured"
            else -> "Unable to check"
        }

        // Recommendations
        if (report.recommendations.isNotEmpty()) {
            binding.tvRecommendations.text = report.recommendations.joinToString("\n\n")
        } else {
            binding.tvRecommendations.text = "No specific recommendations"
        }

        // Scanned at
        binding.tvScannedAt.text = "Scanned: ${report.scannedAt}"
    }
}
