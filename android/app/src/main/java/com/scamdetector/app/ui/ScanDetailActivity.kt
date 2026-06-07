package com.scamdetector.app.ui

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat
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
        WindowCompat.setDecorFitsSystemWindows(window, false)
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

        // Animated circular progress fill: start at 0, animate to actual score
        binding.circularProgress.progress = 0
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
            binding.circularProgress.setProgressCompat(report.riskScore.toInt(), true)
        }, 200)

        // Risk Score number
        binding.tvRiskScore.text = report.riskScore.toInt().toString()

        // 5-tier status
        binding.tvStatus.text = report.status
        val statusColor = statusColor(report.status)
        val color = ContextCompat.getColor(this, statusColor)
        binding.tvStatus.setTextColor(color)
        binding.circularProgress.setIndicatorColor(color)
        binding.cardRiskScore.strokeColor = color

        // Confidence
        binding.tvConfidence.text = "Confidence: ${report.confidence.toInt()}%"

        // ML Prediction
        binding.tvMlPrediction.text = report.mlPrediction
        binding.tvMlConfidence.text = "${report.mlConfidence.toInt()}%"
        binding.progressMl.setIndicatorColor(color)
        binding.progressMl.setProgressCompat(report.mlConfidence.toInt(), true)

        // Domain Age
        binding.tvDomainAge.text = report.domainAgeDays?.let {
            "$it days"
        } ?: "Unable to determine"
        val domainIcon = if ((report.domainAgeDays ?: 365) < 90) R.drawable.ic_warning else R.drawable.ic_check
        binding.ivDomainAge.setImageResource(domainIcon)
        binding.ivDomainAge.imageTintList = ContextCompat.getColorStateList(this,
            if ((report.domainAgeDays ?: 365) < 90) R.color.phishing_red else R.color.safe_green
        )

        // SSL Status
        binding.tvSslStatus.text = when (report.sslValid) {
            true  -> "Valid SSL Certificate"
            false -> "Invalid / Missing SSL"
            null  -> "Unable to check"
        }
        binding.tvSslIssuer.text = "Issuer: ${report.sslIssuer ?: "N/A"}"
        binding.tvSslExpiry.text = "Expires: ${report.sslExpiry ?: "N/A"}"
        val sslIcon = if (report.sslValid == true) R.drawable.ic_check else R.drawable.ic_warning
        binding.ivSslStatus.setImageResource(sslIcon)
        binding.ivSslStatus.imageTintList = ContextCompat.getColorStateList(this,
            if (report.sslValid == true) R.color.safe_green else R.color.phishing_red
        )

        // Brand Impersonation
        binding.cardImpersonation.visibility = View.VISIBLE
        if (report.impersonationRisk) {
            binding.tvImpersonationTarget.text =
                "Possible impersonation of: ${report.impersonationTarget ?: "Unknown Brand"}"
            binding.ivImpersonation.setImageResource(R.drawable.ic_warning)
            binding.ivImpersonation.imageTintList = ContextCompat.getColorStateList(this, R.color.phishing_red)
        } else {
            binding.tvImpersonationTarget.text = "No brand impersonation detected"
            binding.ivImpersonation.setImageResource(R.drawable.ic_check)
            binding.ivImpersonation.imageTintList = ContextCompat.getColorStateList(this, R.color.safe_green)
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
            val urlLen    = features.urlLength
            val https     = features.hasHttps
            val ip        = features.hasIpAddress
            val subs      = features.numSubdomains
            val suspTld   = features.isSuspiciousTld
            val shortened = features.isShortened
            binding.tvUrlLength.text    = "📐 Length: $urlLen"
            binding.tvHttps.text        = "🔒 HTTPS: ${if (https) "Yes ✅" else "No ❌"}"
            binding.tvIpAddress.text    = "🌐 IP in URL: ${if (ip) "Yes ⚠️" else "No"}"
            binding.tvSubdomains.text   = "🔗 Subdomains: $subs"
            binding.tvSuspiciousTld.text = "🚩 Suspicious TLD: ${if (suspTld) "Yes ⚠️" else "No"}"
            binding.tvShortened.text    = "✂️ Shortened URL: ${if (shortened) "Yes ⚠️" else "No"}"
        }

        // Google Safe Browsing
        binding.tvSafeBrowsing.text = when (report.googleSafeBrowsing) {
            "safe"               -> "✅ No threats found"
            "threat_found"       -> "⚠️ Threat detected!"
            "api_not_configured" -> "Not configured"
            else                 -> "Unable to check"
        }

        // Recommendations
        binding.tvRecommendations.text =
            if (report.recommendations.isNotEmpty())
                report.recommendations.joinToString("\n\n")
            else
                "No specific recommendations"

        // Scanned at
        binding.tvScannedAt.text = "Scanned: ${report.scannedAt}"
    }

    /** Map 5-tier status to the corresponding color resource. */
    private fun statusColor(status: String): Int = when (status) {
        "Safe"       -> R.color.safe_green
        "Low Risk"   -> R.color.low_risk_blue
        "Suspicious" -> R.color.suspicious_yellow
        "High Risk"  -> R.color.high_risk_orange
        "Phishing"   -> R.color.phishing_red
        else         -> R.color.suspicious_yellow
    }
}
