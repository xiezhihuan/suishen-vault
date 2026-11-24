package dev.suishen.vault

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import android.view.View
import android.webkit.WebView
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

// 这些入口只能收生命周期事件；没有“批准”、条目编号或用户数据参数。
object Native {
    init { System.loadLibrary("suishen_vault_client_lib") }
    external fun visibility(visible: Boolean)
    external fun closeAll()
    external fun requests()
}

class MainActivity : TauriActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        super.onCreate(savedInstanceState)
        val content = findViewById<View>(android.R.id.content)
        ViewCompat.setOnApplyWindowInsetsListener(content) { view, insets ->
            val edges = insets.getInsets(WindowInsetsCompat.Type.systemBars() or
                WindowInsetsCompat.Type.displayCutout() or WindowInsetsCompat.Type.ime())
            view.setPadding(edges.left, edges.top, edges.right, edges.bottom)
            WindowInsetsCompat.CONSUMED
        }
    }
    override fun onWebViewCreate(webView: WebView) {
        super.onWebViewCreate(webView)
        webView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        webView.importantForContentCapture = View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS
        webView.isSaveEnabled = false
    }
    override fun onStart() {
        super.onStart()
        Native.visibility(true)
        route(intent)
    }
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        route(intent)
    }
    private fun route(intent: Intent?) {
        if (intent?.action == VaultService.REQUESTS) {
            intent.action = null
            Native.requests()
        }
    }
    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        // Android 10+ 只允许有焦点的应用检查当前剪贴板。
        if (hasFocus) VaultClipboard.expire(this)
    }
    override fun onStop() {
        Native.visibility(false)
        Biometrics.cancel()
        super.onStop()
    }
}
