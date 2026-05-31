fn prepare_workspace(sys: &System) -> Result<PathBuf> {
    let ws = std::env::temp_dir().join(format!("l2-ws-{}", sys.name));
    let _ = fs::remove_dir_all(&ws);
    fs::create_dir_all(&ws)?;

    for (name, obj) in &sys.objects {
        let path = ws.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, &obj.content)?;
    }
    Ok(ws)
}

fn exec_isolated(what: &str, _input: Option<&str>, sys_name: &str, workspace: Option<PathBuf>) -> Result<String> {
    let mut cmd = Command::new("unshare");

    let full_command = if let Some(ws) = &workspace {
        format!("cd {} && {}", ws.display(), what)
    } else {
        what.to_string()
    };

    cmd.args(["--fork", "--pid", "--mount-proc", "--net", "sh", "-c", &full_command]);

    cmd.stdout(Stdio::piped())
       .stderr(Stdio::piped());

    let output = cmd.output()?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        let mut msg = format!(
            "[isolated exec in '{}'] failed (code {:?})\n",
            sys_name, output.status.code()
        );
        if !stdout.trim().is_empty() { msg.push_str(&format!("stdout:\n{}\n", stdout)); }
        if !stderr.trim().is_empty() { msg.push_str(&format!("stderr:\n{}\n", stderr)); }

        if stderr.contains("Operation not permitted") || stderr.contains("unshare failed") {
            msg.push_str("\nHint: Full namespace isolation usually requires root on this system.\nTry: sudo ./target/release/l2 exec ...\n");
        }
        return Ok(msg);
    }

    Ok(format!("[isolated via unshare in '{}']\n{}", sys_name, stdout))
}