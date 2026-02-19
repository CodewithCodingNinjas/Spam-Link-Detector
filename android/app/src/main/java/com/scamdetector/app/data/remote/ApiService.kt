package com.scamdetector.app.data.remote

import com.scamdetector.app.data.model.*
import retrofit2.Response
import retrofit2.http.*

/**
 * Retrofit API interface for the Scam Link Detector backend.
 */
interface ApiService {

    /**
     * Scan a URL for threats.
     */
    @POST("check-link")
    suspend fun checkLink(
        @Body request: URLCheckRequest
    ): Response<ThreatReport>

    /**
     * Get scan history from server.
     */
    @GET("scan-history")
    suspend fun getScanHistory(
        @Query("limit") limit: Int = 50,
        @Query("offset") offset: Int = 0,
        @Query("device_id") deviceId: String? = null
    ): Response<ScanHistoryResponse>

    /**
     * Get detailed scan result by ID.
     */
    @GET("scan/{scanId}")
    suspend fun getScanDetail(
        @Path("scanId") scanId: Int
    ): Response<ThreatReport>

    /**
     * Health check.
     */
    @GET("health")
    suspend fun healthCheck(): Response<HealthResponse>
}
