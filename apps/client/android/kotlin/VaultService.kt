package dev.suishen.vault

import android.app.*
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper

class VaultService : Service() {
    companion object {
        const val REQUESTS = "dev.suishen.vault.REQUESTS"
        private const val CLOSE = "dev.suishen.vault.CLOSE"
        private const val OPEN = "vault_open"
        private const val ASK = "vault_requests"
        private const val RUNNING = 101
        private const val PENDING = 102
        // Accessed only on the Android main thread. A late start may never open the listener.
        private var ready: ((Boolean) -> Unit)? = null
        private var active = false

        private fun manager(c: Context) = requireNotNull(c.getSystemService(NotificationManager::class.java))
        fun channels(c: Context) {
            manager(c).createNotificationChannels(listOf(
                NotificationChannel(OPEN, "开放状态", NotificationManager.IMPORTANCE_LOW),
                NotificationChannel(ASK, "授权申请", NotificationManager.IMPORTANCE_HIGH)))
        }
        fun visible(c: Context) = manager(c).areNotificationsEnabled() &&
            manager(c).getNotificationChannel(OPEN)?.importance != NotificationManager.IMPORTANCE_NONE

        fun start(c: Context, done: (Boolean) -> Unit) {
            channels(c)
            if (!visible(c) || ready != null) { done(false); return }
            if (active) { done(true); return }
            ready = done
            try {
                c.startForegroundService(Intent(c, VaultService::class.java))
                Handler(Looper.getMainLooper()).postDelayed({
                    if (ready === done) finishStart(false)
                }, 4500)
            } catch (_: Exception) { finishStart(false) }
        }
        private fun finishStart(ok: Boolean) {
            val callback = ready
            ready = null
            callback?.invoke(ok)
        }
        fun stop(c: Context) {
            active = false
            finishStart(false)
            manager(c).cancel(PENDING)
            c.stopService(Intent(c, VaultService::class.java))
        }
        private fun activity(c: Context, requests: Boolean): PendingIntent {
            val intent = Intent(c, MainActivity::class.java)
                .setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            if (requests) intent.action = REQUESTS
            return PendingIntent.getActivity(c, if (requests) 2 else 1, intent, PendingIntent.FLAG_IMMUTABLE)
        }
        fun notifyRequest(c: Context) {
            if (!active) return
            manager(c).notify(PENDING, Notification.Builder(c, ASK)
                .setSmallIcon(android.R.drawable.ic_lock_lock).setContentTitle("随身密库")
                .setContentText("有新的授权申请，点此核对")
                .setVisibility(Notification.VISIBILITY_SECRET).setAutoCancel(true)
                .setContentIntent(activity(c, true)).build())
        }
    }
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == CLOSE) {
            Native.closeAll()
            stop(this)
            return START_NOT_STICKY
        }
        try {
            channels(this)
            val close = PendingIntent.getService(this, 3, Intent(this, VaultService::class.java)
                .setAction(CLOSE), PendingIntent.FLAG_IMMUTABLE)
            val notice = Notification.Builder(this, OPEN)
                .setSmallIcon(android.R.drawable.ic_lock_lock).setContentTitle("随身密库已开放")
                .setContentText("全部关闭会同时撤销待处理申请和授权码")
                .setOngoing(true).setOnlyAlertOnce(true).setContentIntent(activity(this, false))
                .addAction(Notification.Action.Builder(null, "全部关闭", close).build()).build()
            if (Build.VERSION.SDK_INT >= 34)
                startForeground(RUNNING, notice, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            else startForeground(RUNNING, notice)
            active = ready != null && visible(this)
            finishStart(active)
            if (!active) stopSelf()
        } catch (_: Exception) { finishStart(false); stopSelf() }
        return START_NOT_STICKY
    }
    override fun onTaskRemoved(rootIntent: Intent?) {
        Native.closeAll()
        stop(this)
        super.onTaskRemoved(rootIntent)
    }
    override fun onDestroy() {
        if (active) Native.closeAll()
        active = false
        finishStart(false)
        manager(this).cancel(PENDING)
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }
}
