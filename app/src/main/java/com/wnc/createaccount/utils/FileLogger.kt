package com.wnc.createaccount.utils

import android.content.Context
import android.util.Log
import java.io.File

object FileLogger {
    private const val LOG_FILE_NAME = "ble_log.txt"

    fun writeLog(context: Context, message: String) {
        try {
            // Always write to /Android/data/<package>/files/Logs/
            val logsDir = File(context.getExternalFilesDir(null), "Logs")
            if (!logsDir.exists()) logsDir.mkdirs()

            val logFile = File(logsDir, LOG_FILE_NAME)

            // Add timestamp to each log line
            val timestamp = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", java.util.Locale.getDefault()).format(java.util.Date())
            val fullMessage = "[$timestamp] $message\n"

            logFile.appendText(fullMessage)
        } catch (e: Exception) {
            Log.e("FileLogger", "Error writing log: ${e.message}")
        }
    }
}