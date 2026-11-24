package dev.suishen.vault

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.os.Build
import app.tauri.annotation.Command
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.Plugin

@TauriPlugin
class VaultPlugin(private val host: Activity) : Plugin(host) {
    private fun main(i: Invoke, f: () -> Unit) = host.runOnUiThread {
        try { f() } catch (_: Exception) { i.reject("系统操作未完成") }
    }
    @Command fun startService(i: Invoke) = main(i) {
        val start = {
            VaultService.start(host) { ok ->
                if (ok) i.resolve() else i.reject("请允许常驻通知后重试")
            }
        }
        if (Build.VERSION.SDK_INT >= 33 && host.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED) {
            (host as MainActivity).requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS)) { result ->
                if (result == true) start() else i.reject("请允许常驻通知后重试")
            }
        } else start()
    }
    @Command fun stopService(i: Invoke) = main(i) { VaultService.stop(host); i.resolve() }
    @Command fun requestNotice(i: Invoke) = main(i) { VaultService.notifyRequest(host); i.resolve() }
    @Command fun canNotify(i: Invoke) = main(i) { i.resolveObject(VaultService.visible(host)) }

    @Command fun copy(i: Invoke) = main(i) {
        check(host.hasWindowFocus())
        val a = i.getArgs()
        VaultClipboard.copy(host, a.getString("text"), a.getLong("ms").coerceIn(1000, 120000))
        i.resolve()
    }
    @Command fun clipStamp(i: Invoke) = main(i) { i.resolveObject(VaultClipboard.stamp(host)) }
    @Command fun clearMatching(i: Invoke) = main(i) {
        val a = i.getArgs()
        VaultClipboard.clearMatching(host, a.getString("text"), a.getLong("stamp"))
        i.resolve()
    }

    @Command fun authenticate(i: Invoke) = main(i) {
        check(host.hasWindowFocus())
        Biometrics.authenticate(host, i.getArgs().getBoolean("enroll"), i)
    }
    @Command fun forgetKey(i: Invoke) = main(i) { Biometrics.remove(host); i.resolve() }
}
