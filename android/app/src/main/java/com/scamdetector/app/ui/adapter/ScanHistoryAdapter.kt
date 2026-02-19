package com.scamdetector.app.ui.adapter

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.scamdetector.app.R
import com.scamdetector.app.data.local.ScanHistoryEntity
import com.scamdetector.app.databinding.ItemScanHistoryBinding
import java.text.SimpleDateFormat
import java.util.*

/**
 * RecyclerView adapter for scan history list.
 */
class ScanHistoryAdapter(
    private val onItemClick: (ScanHistoryEntity) -> Unit
) : ListAdapter<ScanHistoryEntity, ScanHistoryAdapter.ViewHolder>(DiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding = ItemScanHistoryBinding.inflate(
            LayoutInflater.from(parent.context), parent, false
        )
        return ViewHolder(binding)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    inner class ViewHolder(
        private val binding: ItemScanHistoryBinding
    ) : RecyclerView.ViewHolder(binding.root) {

        fun bind(scan: ScanHistoryEntity) {
            binding.tvUrl.text = scan.url
            binding.tvRiskScore.text = "${scan.riskScore.toInt()}"
            binding.tvStatus.text = scan.status

            // Format date
            val dateFormat = SimpleDateFormat("MMM dd, yyyy HH:mm", Locale.getDefault())
            binding.tvDate.text = dateFormat.format(Date(scan.scannedAt))

            // Status color
            val statusColor = when (scan.status) {
                "Safe" -> R.color.safe_green
                "Suspicious" -> R.color.suspicious_yellow
                "Phishing" -> R.color.phishing_red
                else -> R.color.suspicious_yellow
            }
            binding.tvStatus.setTextColor(
                ContextCompat.getColor(binding.root.context, statusColor)
            )
            binding.viewStatusIndicator.setBackgroundColor(
                ContextCompat.getColor(binding.root.context, statusColor)
            )

            // Click handler
            binding.root.setOnClickListener {
                onItemClick(scan)
            }
        }
    }

    class DiffCallback : DiffUtil.ItemCallback<ScanHistoryEntity>() {
        override fun areItemsTheSame(
            oldItem: ScanHistoryEntity, newItem: ScanHistoryEntity
        ): Boolean = oldItem.id == newItem.id

        override fun areContentsTheSame(
            oldItem: ScanHistoryEntity, newItem: ScanHistoryEntity
        ): Boolean = oldItem == newItem
    }
}
