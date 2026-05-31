// === Real host isolation for exec ===

fn exec_isolated(what: &str, input: Option<&str>, sys_name: &str) -> Result<String> {
    let mut cmd = Command::new("unshare");

    // Use sh -c so that the user's command (including spaces, pipes, quotes, etc.)
    // is properly interpreted. This makes the UX much better.
    cmd.args(["--fork", "--pid", "--mount-proc", "--net", "sh", "-c", what]);

    cmd.stdout(Stdio::piped())
       .stderr(Stdio::piped());

    let output = cmd.output()?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        let mut msg = format!(
            "[isolated exec in '{}'] command failed (code {:?})\n",
            sys_name, output.status.code()
        );

        if !stdout.trim().is_empty() {
            msg.push_str(&format!("stdout:\n{}\n", stdout));
        }
        if !stderr.trim().is_empty() {
            msg.push_str(&format!("stderr:\n{}\n", stderr));
        }

        // Give helpful hints for common unshare failures
        if stderr.contains("Operation not permitted") || stderr.contains("unshare failed") {
            msg.push_str("\nHint: Full namespace isolation often requires root or specific capabilities.
Try: sudo ./target/release/l2 exec ...\n");
            msg.push_str("On many systems you can also enable user namespaces to avoid sudo.");
        }

        return Ok(msg);
    }

    Ok(format!("[isolated via unshare in '{}']\n{}", sys_name, stdout))
}
