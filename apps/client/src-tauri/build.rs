/// 与 `src/commands.rs` 一致。列出后每条命令都要在 capability 里显式授予。
const COMMANDS: &[&str] = &[
    "poll",
    "touch",
    "setup_begin",
    "setup_confirm",
    "cancel_flow",
    "unlock",
    "biometric",
    "lock",
    "recovery_begin",
    "recovery_reissue",
    "recovery_confirm",
    "change_password",
    "list_items",
    "get_item",
    "reveal_field",
    "copy_field",
    "copy_text",
    "save_item",
    "parse_paste",
    "pasteboard_stamp",
    "save_paste",
    "draft_permission",
    "draft_inbox",
    "accept_draft",
    "reject_drafts",
    "item_action",
    "empty_trash",
    "totp_code",
    "generate",
    "open_service",
    "close_service",
    "relay_claim",
    "relay_forget",
    "pairing_begin",
    "pairing_accept",
    "pairing_cancel",
    "list_clients",
    "add_client",
    "rename_client",
    "revoke_client",
    "resume_client",
    "decide",
    "request_state",
    "audit",
    "mcp_config",
    "select_document",
    "import_csv",
    "delete_csv",
    "export_backup",
    "pick_package",
    "restore_backup",
    "migration_import",
    "migration_begin",
    "migration_cancel",
    "migration_confirm",
    "wipe_retired",
    "set_aside",
    "set_settings",
];

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        // 拒绝仅有默认 Tauri 清单（允许备份、没有前台服务）的裸工程。
        let manifest = "gen/android/app/src/main/AndroidManifest.xml";
        println!("cargo:rerun-if-changed={manifest}");
        assert!(
            std::fs::read(manifest)
                .is_ok_and(|bytes| bytes == include_bytes!("../android/AndroidManifest.xml")),
            "请从仓库根目录运行 npm run android:build 安装本项目的 Android 清单"
        );
    }
    let manifest = tauri_build::AppManifest::new().commands(COMMANDS);
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest))
        .expect("tauri-build 失败");
}
