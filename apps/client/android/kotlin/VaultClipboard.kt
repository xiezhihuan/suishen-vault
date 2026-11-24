package dev.suishen.vault

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock
import java.util.UUID

object VaultClipboard {
    private const val OWNER = "dev.suishen.vault.copy"
    private var owned: String? = null
    private var expires = 0L
    private fun manager(c: Context) = requireNotNull(c.getSystemService(ClipboardManager::class.java))
    fun copy(c: Context, text: String, ttl: Long) {
        val id = UUID.randomUUID().toString()
        val clip = ClipData.newPlainText("随身密库", text)
        clip.description.extras = PersistableBundle().apply {
            // ClipDescription.EXTRA_IS_SENSITIVE 的值，兼容 API 29。
            putBoolean("android.content.extra.IS_SENSITIVE", true)
            putString(OWNER, id)
        }
        manager(c).setPrimaryClip(clip)
        owned = id
        expires = SystemClock.elapsedRealtime() + ttl
        Handler(Looper.getMainLooper()).postDelayed({ expire(c) }, ttl)
    }
    fun expire(c: Context) { if (SystemClock.elapsedRealtime() >= expires) clearOwned(c) }
    fun clearOwned(c: Context) {
        val id = owned ?: return
        try {
            val m = manager(c)
            val desc = m.primaryClipDescription ?: return
            if (desc.extras?.getString(OWNER) == id) m.clearPrimaryClip()
            owned = null
        } catch (_: RuntimeException) { /* 没有焦点时系统可拒绝，回到前台重试。 */ }
    }
    fun stamp(c: Context): Long = manager(c).primaryClipDescription?.timestamp ?: 0L
    fun clearMatching(c: Context, original: String, expected: Long) {
        val m = manager(c)
        val clip = m.primaryClip ?: return
        if (expected > 0 && clip.description.timestamp == expected && clip.itemCount == 1 &&
            clip.getItemAt(0).text?.toString() == original && stamp(c) == expected) m.clearPrimaryClip()
    }
}
