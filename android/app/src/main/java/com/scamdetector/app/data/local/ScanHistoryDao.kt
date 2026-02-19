package com.scamdetector.app.data.local

import androidx.lifecycle.LiveData
import androidx.room.*

/**
 * DAO for scan history database operations.
 */
@Dao
interface ScanHistoryDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(scan: ScanHistoryEntity): Long

    @Query("SELECT * FROM scan_history ORDER BY scannedAt DESC")
    fun getAllScans(): LiveData<List<ScanHistoryEntity>>

    @Query("SELECT * FROM scan_history ORDER BY scannedAt DESC LIMIT :limit")
    fun getRecentScans(limit: Int): LiveData<List<ScanHistoryEntity>>

    @Query("SELECT * FROM scan_history WHERE id = :id")
    suspend fun getScanById(id: Long): ScanHistoryEntity?

    @Query("SELECT * FROM scan_history WHERE url = :url ORDER BY scannedAt DESC LIMIT 1")
    suspend fun getLatestScanForUrl(url: String): ScanHistoryEntity?

    @Query("SELECT COUNT(*) FROM scan_history")
    suspend fun getCount(): Int

    @Query("SELECT COUNT(*) FROM scan_history WHERE status = :status")
    suspend fun getCountByStatus(status: String): Int

    @Delete
    suspend fun delete(scan: ScanHistoryEntity)

    @Query("DELETE FROM scan_history")
    suspend fun deleteAll()

    @Query("DELETE FROM scan_history WHERE scannedAt < :timestamp")
    suspend fun deleteOlderThan(timestamp: Long)
}
