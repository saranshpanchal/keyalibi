use keyalibi::jail::{self, JailPlan, Overlay};
use std::fs;
use std::sync::Mutex;

static JAIL_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn child_cat_env_sees_phantom_and_host_file_is_unchanged() {
    let _guard = JAIL_LOCK.lock().unwrap();
    let dir = std::env::temp_dir().join(format!(
        "keyalibi-jail-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let env_path = dir.join(".env");
    let real = "OPENAI_API_KEY=sk-REAL-SECRET-VALUE-1234567890\nOTHER=keep\n";
    let phantom = "OPENAI_API_KEY=sk-PHANTOM-VALUE-KEYALIBI-123456\nOTHER=keep\n";
    fs::write(&env_path, real).unwrap();

    let captured = jail::capture(JailPlan {
        workspace: dir.clone(),
        argv: vec!["/bin/cat".into(), ".env".into()],
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        overlays: vec![Overlay {
            target: env_path.clone(),
            contents: phantom.to_string(),
        }],
        masks: Vec::new(),
        capture: true,
    })
    .expect("jail capture");

    if !captured.namespaced {
        eprintln!(
            "skipping jail overlay test: user namespaces unavailable{}",
            captured
                .warning
                .as_ref()
                .map(|warning| format!(" ({warning})"))
                .unwrap_or_default()
        );
        let _ = fs::remove_dir_all(&dir);
        return;
    }

    let stdout = String::from_utf8_lossy(&captured.stdout);
    let stderr = String::from_utf8_lossy(&captured.stderr);
    assert!(captured.status.success(), "cat failed: {stderr}");
    assert!(
        stdout.contains("sk-PHANTOM-VALUE-KEYALIBI-123456"),
        "child stdout did not contain the phantom: {stdout}"
    );
    assert!(
        !stdout.contains("sk-REAL-SECRET-VALUE-1234567890"),
        "child stdout contained the real secret"
    );
    assert!(stdout.contains("OTHER=keep"));
    let host = fs::read_to_string(&env_path).unwrap();
    assert!(host.contains("sk-REAL-SECRET-VALUE-1234567890"));
    assert!(!host.contains("sk-PHANTOM-VALUE-KEYALIBI-123456"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn umount_inside_the_child_does_not_reveal_the_real_env() {
    let _guard = JAIL_LOCK.lock().unwrap();
    let dir = std::env::temp_dir().join(format!(
        "keyalibi-umount-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let env_path = dir.join(".env");
    let real = "TOKEN=sk-REAL-SECRET-VALUE-1234567890\n";
    let phantom = "TOKEN=sk-PHANTOM-VALUE-KEYALIBI-123456\n";
    fs::write(&env_path, real).unwrap();

    let script = "umount .env >/dev/null 2>&1; echo u1:$?; umount -l .env >/dev/null 2>&1; echo u2:$?; cat .env";
    let captured = jail::capture(JailPlan {
        workspace: dir.clone(),
        argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        overlays: vec![Overlay {
            target: env_path.clone(),
            contents: phantom.to_string(),
        }],
        masks: Vec::new(),
        capture: true,
    })
    .expect("jail capture");

    if !captured.namespaced {
        eprintln!(
            "skipping umount jail test: user namespaces unavailable{}",
            captured
                .warning
                .as_ref()
                .map(|warning| format!(" ({warning})"))
                .unwrap_or_default()
        );
        let _ = fs::remove_dir_all(&dir);
        return;
    }

    let stdout = String::from_utf8_lossy(&captured.stdout);
    let stderr = String::from_utf8_lossy(&captured.stderr);
    assert!(
        captured.status.success(),
        "shell failed: {stderr}\n{stdout}"
    );
    assert!(
        stdout.contains("u1:") && !stdout.contains("u1:0"),
        "umount should fail: {stdout}"
    );
    assert!(
        stdout.contains("u2:") && !stdout.contains("u2:0"),
        "lazy umount should fail: {stdout}"
    );
    assert!(
        stdout.contains("sk-PHANTOM-VALUE-KEYALIBI-123456"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("sk-REAL-SECRET-VALUE-1234567890"),
        "{stdout}"
    );
    let host = fs::read_to_string(&env_path).unwrap();
    assert!(host.contains("sk-REAL-SECRET-VALUE-1234567890"));
    let _ = fs::remove_dir_all(&dir);
}
