package com.scamdetector.app.ui

import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.activity.viewModels
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import com.scamdetector.app.R
import com.scamdetector.app.databinding.ActivityMainBinding
import com.scamdetector.app.ui.adapter.ScanHistoryAdapter

/**
 * Main activity with URL input, scan button, result display, and history.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val viewModel: MainViewModel by viewModels()
    private lateinit var historyAdapter: ScanHistoryAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupUI()
        setupObservers()
        handleIncomingIntent(intent)
        checkClipboard()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIncomingIntent(intent)
    }

    private fun setupUI() {
        // Scan button
        binding.btnScan.setOnClickListener {
            val url = binding.etUrl.text.toString().trim()
            if (url.isNotEmpty()) {
                viewModel.scanUrl(url)
            } else {
                binding.tilUrl.error = "Please enter a URL"
            }
        }

        // Paste button
        binding.btnPaste.setOnClickListener {
            pasteFromClipboard()
        }

        // Clear button
        binding.btnClear.setOnClickListener {
            binding.etUrl.text?.clear()
            binding.tilUrl.error = null
            hideResultCard()
        }

        // QR Scanner button
        binding.btnQrScan.setOnClickListener {
            startActivity(Intent(this, QRScannerActivity::class.java))
        }

        // History RecyclerView
        historyAdapter = ScanHistoryAdapter { scan ->
            val intent = Intent(this, ScanDetailActivity::class.java)
            intent.putExtra(ScanDetailActivity.EXTRA_SCAN_ID, scan.id)
            startActivity(intent)
        }
        binding.rvHistory.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = historyAdapter
        }

        // Clear history
        binding.btnClearHistory.setOnClickListener {
            AlertDialog.Builder(this)
                .setTitle("Clear History")
                .setMessage("Are you sure you want to delete all scan history?")
                .setPositiveButton("Clear") { _, _ ->
                    viewModel.clearHistory()
                    Toast.makeText(this, "History cleared", Toast.LENGTH_SHORT).show()
                }
                .setNegativeButton("Cancel", null)
                .show()
        }

        // URL input clear error on typing
        binding.etUrl.setOnFocusChangeListener { _, _ ->
            binding.tilUrl.error = null
        }
    }

    private fun setupObservers() {
        // Scan state
        viewModel.scanState.observe(this) { state ->
            when (state) {
                is ScanState.Loading -> showLoading()
                is ScanState.Success -> showResult(state.report)
                is ScanState.Error -> showError(state.message)
                is ScanState.Idle -> hideResultCard()
            }
        }

        // Scan history
        viewModel.scanHistory.observe(this) { scans ->
            historyAdapter.submitList(scans)
            binding.tvNoHistory.visibility = if (scans.isEmpty()) View.VISIBLE else View.GONE
            binding.rvHistory.visibility = if (scans.isNotEmpty()) View.VISIBLE else View.GONE
        }

        // Stats
        viewModel.stats.observe(this) { stats ->
            binding.tvStatTotal.text = stats.total.toString()
            binding.tvStatSafe.text = stats.safe.toString()
            binding.tvStatSuspicious.text = stats.suspicious.toString()
            binding.tvStatPhishing.text = stats.phishing.toString()
        }
    }

    /**
     * Handle shared intents (Share-to-Scan feature).
     */
    private fun handleIncomingIntent(intent: Intent?) {
        when (intent?.action) {
            Intent.ACTION_SEND -> {
                if (intent.type == "text/plain") {
                    val sharedText = intent.getStringExtra(Intent.EXTRA_TEXT)
                    sharedText?.let { text ->
                        val url = extractUrl(text)
                        if (url != null) {
                            binding.etUrl.setText(url)
                            viewModel.scanUrl(url)
                        } else {
                            binding.etUrl.setText(text)
                        }
                    }
                }
            }
            Intent.ACTION_VIEW -> {
                intent.dataString?.let { url ->
                    binding.etUrl.setText(url)
                    viewModel.scanUrl(url)
                }
            }
        }
    }

    /**
     * Check clipboard for URLs and offer to scan.
     */
    private fun checkClipboard() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = clipboard.primaryClip
        if (clip != null && clip.itemCount > 0) {
            val text = clip.getItemAt(0).text?.toString() ?: return
            val url = extractUrl(text)
            if (url != null && binding.etUrl.text.isNullOrEmpty()) {
                AlertDialog.Builder(this)
                    .setTitle("URL Detected in Clipboard")
                    .setMessage("Scan this link?\n\n$url")
                    .setPositiveButton("Scan") { _, _ ->
                        binding.etUrl.setText(url)
                        viewModel.scanUrl(url)
                    }
                    .setNegativeButton("Dismiss", null)
                    .show()
            }
        }
    }

    private fun pasteFromClipboard() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = clipboard.primaryClip
        if (clip != null && clip.itemCount > 0) {
            val text = clip.getItemAt(0).text?.toString()
            if (text != null) {
                val url = extractUrl(text) ?: text
                binding.etUrl.setText(url)
                binding.tilUrl.error = null
            }
        } else {
            Toast.makeText(this, "Clipboard is empty", Toast.LENGTH_SHORT).show()
        }
    }

    /**
     * Extract URL from text.
     */
    private fun extractUrl(text: String): String? {
        val urlPattern = Regex(
            """https?://[^\s<>"{}|\\^`\[\]]+""",
            RegexOption.IGNORE_CASE
        )
        return urlPattern.find(text)?.value
    }

    private fun showLoading() {
        binding.cardResult.visibility = View.VISIBLE
        binding.layoutResultContent.visibility = View.GONE
        binding.progressBar.visibility = View.VISIBLE
        binding.tvError.visibility = View.GONE
        binding.btnScan.isEnabled = false
        binding.btnScan.text = "Scanning..."
    }

    private fun showResult(report: com.scamdetector.app.data.model.ThreatReport) {
        binding.progressBar.visibility = View.GONE
        binding.layoutResultContent.visibility = View.VISIBLE
        binding.tvError.visibility = View.GONE
        binding.btnScan.isEnabled = true
        binding.btnScan.text = "Scan Now"

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
        binding.tvStatus.setTextColor(ContextCompat.getColor(this, statusColor))
        binding.circularProgress.setIndicatorColor(ContextCompat.getColor(this, statusColor))

        // ML Prediction
        binding.tvMlPrediction.text = report.mlPrediction
        binding.tvConfidence.text = "${report.confidence}%"

        // Details summary
        binding.tvDomainAge.text = report.domainAgeDays?.let { "${it} days" } ?: "N/A"
        binding.tvSslStatus.text = when (report.sslValid) {
            true -> "Valid"
            false -> "Invalid"
            null -> "N/A"
        }
        binding.tvImpersonation.text = if (report.impersonationRisk)
            "Yes - ${report.impersonationTarget ?: "Unknown"}"
        else "No"

        // Keywords
        binding.tvKeywords.text = if (report.suspiciousKeywords.isNotEmpty())
            report.suspiciousKeywords.joinToString(", ")
        else "None found"

        // View Details button
        binding.btnViewDetails.setOnClickListener {
            val intent = Intent(this, ScanDetailActivity::class.java)
            intent.putExtra(ScanDetailActivity.EXTRA_REPORT_JSON,
                com.google.gson.Gson().toJson(report))
            startActivity(intent)
        }
    }

    private fun showError(message: String) {
        binding.progressBar.visibility = View.GONE
        binding.layoutResultContent.visibility = View.GONE
        binding.tvError.visibility = View.VISIBLE
        binding.tvError.text = message
        binding.cardResult.visibility = View.VISIBLE
        binding.btnScan.isEnabled = true
        binding.btnScan.text = "Scan Now"
    }

    private fun hideResultCard() {
        binding.cardResult.visibility = View.GONE
    }
}
