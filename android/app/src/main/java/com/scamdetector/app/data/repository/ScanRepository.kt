package com.scamdetector.app.data.repository

import android.content.Context
import androidx.lifecycle.LiveData
import com.google.gson.Gson
import com.scamdetector.app.data.local.AppDatabase
import com.scamdetector.app.data.local.ScanHistoryEntity
import com.scamdetector.app.data.model.ThreatReport
import com.scamdetector.app.data.model.URLCheckRequest
import com.scamdetector.app.data.remote.RetrofitClient

/**
 * Repository that mediates between remote API and local database.
 */
class ScanRepository(context: Context) {

    private val apiService = RetrofitClient.apiService
    private val dao = AppDatabase.getInstance(context).scanHistoryDao()
    private val gson = Gson()

    /**
     * Scan a URL by sending it to the backend API.
     * Saves the result to local database on success.
     */
    suspend fun scanUrl(url: String, deviceId: String? = null): Result<ThreatReport> {
        return try {
            val request = URLCheckRequest(url = url, deviceId = deviceId)
            val response = apiService.checkLink(request)

            if (response.isSuccessful && response.body() != null) {
                val report = response.body()!!

                // Save to local database
                saveScanToLocal(report)

                Result.success(report)
            } else {
                val errorBody = response.errorBody()?.string() ?: "Unknown error"
                Result.failure(Exception("API Error ${response.code()}: $errorBody"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Save a threat report to local Room database.
     */
    private suspend fun saveScanToLocal(report: ThreatReport) {
        val entity = ScanHistoryEntity(
            url = report.url,
            riskScore = report.riskScore,
            status = report.status,
            mlPrediction = report.mlPrediction,
            mlConfidence = report.mlConfidence,
            domainAgeDays = report.domainAgeDays,
            sslValid = report.sslValid,
            impersonationRisk = report.impersonationRisk,
            impersonationTarget = report.impersonationTarget,
            suspiciousKeywords = gson.toJson(report.suspiciousKeywords),
            confidence = report.confidence,
            recommendations = gson.toJson(report.recommendations),
            scannedAt = System.currentTimeMillis(),
            responseJson = gson.toJson(report)
        )
        dao.insert(entity)
    }

    /**
     * Get all scan history from local database.
     */
    fun getAllScans(): LiveData<List<ScanHistoryEntity>> = dao.getAllScans()

    /**
     * Get recent scans from local database.
     */
    fun getRecentScans(limit: Int = 20): LiveData<List<ScanHistoryEntity>> =
        dao.getRecentScans(limit)

    /**
     * Get a scan by its local ID.
     */
    suspend fun getScanById(id: Long): ScanHistoryEntity? = dao.getScanById(id)

    /**
     * Convert a ScanHistoryEntity back to ThreatReport.
     */
    fun entityToThreatReport(entity: ScanHistoryEntity): ThreatReport? {
        return try {
            entity.responseJson?.let { gson.fromJson(it, ThreatReport::class.java) }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Delete all scan history.
     */
    suspend fun clearHistory() = dao.deleteAll()

    /**
     * Get scan count.
     */
    suspend fun getScanCount(): Int = dao.getCount()

    /**
     * Get scan count by status.
     */
    suspend fun getCountByStatus(status: String): Int = dao.getCountByStatus(status)
}
