package com.scamdetector.app.ui

import android.app.Application
import androidx.lifecycle.*
import com.scamdetector.app.data.local.ScanHistoryEntity
import com.scamdetector.app.data.model.ThreatReport
import com.scamdetector.app.data.repository.ScanRepository
import kotlinx.coroutines.launch

/**
 * ViewModel for the main scanner screen.
 * Handles URL scanning and scan history.
 */
class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = ScanRepository(application)

    // Scan state
    private val _scanState = MutableLiveData<ScanState>()
    val scanState: LiveData<ScanState> = _scanState

    // Current threat report
    private val _currentReport = MutableLiveData<ThreatReport?>()
    val currentReport: LiveData<ThreatReport?> = _currentReport

    // Scan history
    val scanHistory: LiveData<List<ScanHistoryEntity>> = repository.getRecentScans(50)

    // Stats
    private val _stats = MutableLiveData<ScanStats>()
    val stats: LiveData<ScanStats> = _stats

    /**
     * Scan a URL for threats.
     */
    fun scanUrl(url: String) {
        if (url.isBlank()) {
            _scanState.value = ScanState.Error("Please enter a valid URL")
            return
        }

        _scanState.value = ScanState.Loading
        _currentReport.value = null

        viewModelScope.launch {
            val result = repository.scanUrl(url)
            result.fold(
                onSuccess = { report ->
                    _currentReport.value = report
                    _scanState.value = ScanState.Success(report)
                    updateStats()
                },
                onFailure = { error ->
                    _scanState.value = ScanState.Error(
                        error.message ?: "Unknown error occurred"
                    )
                }
            )
        }
    }

    /**
     * Get detailed report for a history item.
     */
    fun loadScanDetail(scanId: Long) {
        viewModelScope.launch {
            val entity = repository.getScanById(scanId)
            entity?.let {
                val report = repository.entityToThreatReport(it)
                _currentReport.value = report
            }
        }
    }

    /**
     * Clear all scan history.
     */
    fun clearHistory() {
        viewModelScope.launch {
            repository.clearHistory()
            updateStats()
        }
    }

    /**
     * Update stats.
     */
    private fun updateStats() {
        viewModelScope.launch {
            val total = repository.getScanCount()
            val safe = repository.getCountByStatus("Safe")
            val suspicious = repository.getCountByStatus("Suspicious")
            val phishing = repository.getCountByStatus("Phishing")
            _stats.value = ScanStats(total, safe, suspicious, phishing)
        }
    }

    init {
        updateStats()
    }
}

/**
 * Represents the state of a URL scan operation.
 */
sealed class ScanState {
    data object Idle : ScanState()
    data object Loading : ScanState()
    data class Success(val report: ThreatReport) : ScanState()
    data class Error(val message: String) : ScanState()
}

/**
 * Scan statistics.
 */
data class ScanStats(
    val total: Int = 0,
    val safe: Int = 0,
    val suspicious: Int = 0,
    val phishing: Int = 0
)
