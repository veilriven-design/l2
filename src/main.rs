fn get_home_for_user(username: &str) -> Option<String> {
    let output = std::process::Command::new("getent")
        .args(["passwd", username])
        .output()
        .ok()?;

    let line = std::str::from_utf8(&output.stdout).ok()?;
    let home = line.split(':').nth(5)?;
    Some(home.trim().to_string())
}

fn data_dir() -> PathBuf {
    // Highest priority: explicit override
    if let Ok(dir) = std::env::var("L2_DATA_DIR") {
        return PathBuf::from(dir);
    }

    // If running under sudo, try to use the original user's home directory
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if let Some(home) = get_home_for_user(&sudo_user) {
            return PathBuf::from(home).join(".l2");
        }
    }

    // Normal case
    let home = std::env::var("HOME").expect("HOME must be set");
    PathBuf::from(home).join(".l2")
}