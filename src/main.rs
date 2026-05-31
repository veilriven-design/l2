//! l2 - Focused Latticra substrate (host prototype with persistence)
//!
//! State lives in ~/.l2/state.json (override with L2_DATA_DIR).
//!
//! When run under sudo, it automatically uses the original user's home directory.

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
mod sandbox;

#[derive(Parser, Debug)]
#[command(name = "l2", version, about = "Minimal high-assurance substrate (host prototype with persistence)", long_about = None)]
struct Cli {
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Create {
        name: String,
        #[arg(long, default_value = "default")]
        policy: String,
    },
    Destroy {
        name: String,
    },
    List {
        name: Option<String>,
    },
    Put {
        sys: String,
        name: String,
        #[arg(
            long,
            default_value = "data",
            help = "Type: data, code, credential, mcp_server"
        )]
        r#type: String,
        #[arg(long, help = "Inline content")]
        content: Option<String>,
    },
    Get {
        sys: String,
        name: String,
    },
    Exec {
        /// Policy to use for oneshot execution (e.g. "strict", "strict-mcp", "default").
        /// Only meaningful for one-shot mode (`l2 exec hello.py`).
        #[arg(long)]
        policy: Option<String>,

        /// Flexible arguments.
        /// - 1 arg that is a local file with code extension/shebang → oneshot execution
        /// - 2+ args → first is system name, rest forms the command (or bare name for dispatch)
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            help = "System and command, or just a local code file for oneshot (e.g. hello.py, mysys hello.py, 'cat file.txt')"
        )]
        args: Vec<String>,

        #[arg(long)]
        input: Option<String>,
    },
    Revoke {
        sys: String,
        grant: String,
    },
    Status {
        name: Option<String>,
    },
    Sel4Setup,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct System {
    id: String,
    name: String,
    policy: String,
    created_at: String,
    objects: HashMap<String, Object>,
    grants: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Object {
    name: String,
    r#type: String,
    content: String,
    size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Substrate {
    systems: HashMap<String, System>,
    next_id: u64,
}

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

/// Returns true if this process is running with root privileges, either directly
/// or via sudo (in which case SUDO_USER is set in the environment).
fn is_privileged() -> bool {
    if std::env::var_os("SUDO_USER").is_some() || std::env::var_os("SUDO_UID").is_some() {
        return true;
    }
    nix::unistd::Uid::effective().is_root()
}

/// Re-executes the current l2 binary under sudo for `exec` (and only exec).
/// This ensures namespace isolation (unshare) and strict Landlock/no_new_privs
/// can be applied with full privileges. Uses current_exe() so it works for
/// cargo-installed binaries (~/.cargo/bin/l2) as well as local builds.
fn escalate_to_root_for_exec() -> ! {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("✗ failed to locate current l2 binary for sudo escalation: {e}");
            eprintln!("  Hint: run the full path explicitly under sudo, e.g.");
            eprintln!("    sudo /path/to/l2 exec ...");
            std::process::exit(1);
        }
    };

    let args: Vec<String> = std::env::args().skip(1).collect();

    // Inform the user (non-json path; json users will see sudo's output or errors)
    eprintln!("→ requesting root for isolated exec (namespaces + strict policy)...");
    eprintln!("   sudo {} {}", exe.display(), args.join(" "));

    let mut cmd = Command::new("sudo");
    cmd.arg(&exe).args(&args);

    match cmd.status() {
        Ok(status) => {
            std::process::exit(status.code().unwrap_or(1));
        }
        Err(e) => {
            eprintln!("✗ sudo failed: {e}");
            eprintln!("  You may need to manually prefix with sudo using the binary path:");
            eprintln!("    sudo {} {}", exe.display(), args.join(" "));
            std::process::exit(1);
        }
    }
}

/// Heuristic validation: if the exec command appears to reference a file that
/// was `put` into the system (e.g. `./task`, `sh task.rs`, `cat ./foo.txt`),
/// verify it actually exists in the stored objects. This gives a clear,
/// high-quality error *before* we do the sudo escalation dance for a user
/// mistake.
fn validate_exec_target_references_real_object(
    what: &str,
    system: &System,
    sys_name: &str,
    json: bool,
) {
    let tokens: Vec<&str> = what.split_whitespace().collect();
    if tokens.is_empty() {
        return;
    }

    for (i, tok) in tokens.iter().enumerate() {
        let candidate = tok
            .trim_start_matches("./")
            .trim_start_matches(".\\")
            .to_string();

        if candidate.is_empty() || candidate.starts_with('/') || candidate.contains("..") {
            continue;
        }

        // Common interpreters / tools: the *next* token is often the file we care about
        let is_interpreter = matches!(
            *tok,
            "sh" | "bash"
                | "dash"
                | "zsh"
                | "python"
                | "python3"
                | "node"
                | "cat"
                | "less"
                | "head"
                | "tail"
                | "more"
        );

        let target_to_check = if is_interpreter {
            if let Some(next) = tokens.get(i + 1) {
                let c = next
                    .trim_start_matches("./")
                    .trim_start_matches(".\\")
                    .to_string();
                if c.starts_with('/') || c.contains("..") || c.is_empty() {
                    continue;
                }
                c
            } else {
                continue;
            }
        } else if !tok.starts_with("./") && tok.contains('/') {
            // Looks like an absolute or complex path that isn't one of our objects
            continue;
        } else {
            candidate
        };

        // Check for missing first (existing "did you mean" logic)
        if !system.objects.contains_key(&target_to_check) {
            let display_target = if is_interpreter {
                tokens.get(i + 1).unwrap_or(tok)
            } else {
                tok
            };
            let avail = list_available_objects(system);

            let mut msg = format!(
                "exec target '{}' not found in system '{}' workspace (available objects: {})",
                display_target, sys_name, avail
            );

            if let Some(sugg) = find_suggestion(display_target, system) {
                msg.push_str(&format!("\n  Did you mean '{}'?", sugg));
            }

            if let Some(cmd) = suggest_working_command(system) {
                msg.push_str(&format!("\n  Try: l2 exec {} '{}'", sys_name, cmd));
            }

            error(&msg, json);
        }

        // NEW: The object exists, but the user is trying to *directly execute* a code
        // object (e.g. `./task` or `task.rs` after `put --type code`). Give a clear
        // conceptual explanation instead of letting the shell fail later.
        if let Some(obj) = system.objects.get(&target_to_check) {
            let is_direct_exec = !is_interpreter && (tok.starts_with("./") || !tok.contains('/'));

            if is_direct_exec && obj.r#type == "code" {
                let mut msg = format!(
                    "Direct execution of '{}' is not supported (object type = code).\n\n\
                     `l2 exec` runs an arbitrary shell command you provide inside the\n\
                     isolated workspace. `--type code` simply stores text content as a file.\n\n\
                     The file is present. You can inspect or process it with normal commands:",
                    target_to_check
                );
                msg.push_str(&format!(
                    "\n  l2 exec {} 'cat {}'",
                    sys_name, target_to_check
                ));
                msg.push_str(&format!(
                    "\n  l2 exec {} 'head -20 {}'",
                    sys_name, target_to_check
                ));

                if target_to_check.ends_with(".rs") {
                    msg.push_str(
                        "\n\n\
                         This is Rust source. To actually compile + run it you would need\n\
                         a Rust toolchain available inside the isolated environment and\n\
                         would typically do something like:\n\
                           l2 exec <sys> 'sh -c \"rustc task.rs -o task && ./task\"'",
                    );
                } else {
                    msg.push_str(
                        "\n\n\
                         If this were a shell script you could run it with:\n\
                           l2 exec <sys> 'sh <file>'",
                    );
                }
                error(&msg, json);
            }
        }
    }
}

fn list_available_objects(system: &System) -> String {
    if system.objects.is_empty() {
        "none — use `l2 put <sys> <name> ...` first".to_string()
    } else {
        let mut v: Vec<_> = system.objects.keys().cloned().collect();
        v.sort();
        v.join(", ")
    }
}

/// Very lightweight "did you mean" for the extremely common case of users
/// stripping the extension or writing `./task` after `put task.rs`.
fn find_suggestion(asked: &str, system: &System) -> Option<String> {
    let base = asked
        .trim_start_matches("./")
        .trim_start_matches(".\\")
        .trim_end_matches(".rs")
        .trim_end_matches(".sh")
        .trim_end_matches(".txt")
        .to_lowercase();

    if base.is_empty() {
        return None;
    }

    system
        .objects
        .keys()
        .find(|name| {
            let n = name.to_lowercase();
            n == base
                || n == format!("{}.rs", base)
                || n == format!("{}.sh", base)
                || n == format!("{}.txt", base)
                || n.starts_with(&base)
                || base.starts_with(n.trim_end_matches(".rs").trim_end_matches(".sh"))
        })
        .cloned()
}

/// Suggest a safe, always-working first command the user can run against
/// an object they actually stored (great for discovery after a near-miss).
fn suggest_working_command(system: &System) -> Option<String> {
    let mut names: Vec<_> = system.objects.keys().cloned().collect();
    names.sort();
    names.first().map(|name| format!("cat {}", name))
}

// -----------------------------------------------------------------------------
// Small styling helpers for a more polished terminal experience
// (uses the existing `colored` dependency — no new TCB cost)
// -----------------------------------------------------------------------------
#[allow(dead_code)]
fn l2_prefix() -> String {
    "l2".bright_blue().bold().to_string()
}

fn dispatch_prefix() -> String {
    "[dispatch]".magenta().dimmed().to_string()
}

fn oneshot_prefix() -> String {
    "[oneshot]".cyan().bold().to_string()
}

// -----------------------------------------------------------------------------
// Language dispatch & oneshot support (client-side sugar only – see design doc
// /tmp/grok-design-doc-40f3ed91.md for full rationale and PR plan).
// These functions are pure and deliberately easy to extend ("all the way" host
// language support via shebang + small curated static table).
//
// NOTE: Some of these are currently only called from tests. They will be wired
// into the Exec path and oneshot logic in PR 2. The dead_code allowance is
// intentional during the foundation phase.
// -----------------------------------------------------------------------------
#[allow(dead_code)]
/// Returns true if the name looks like it has a common source/script extension.
/// This is deliberately broad ("all the way" on the host) but still conservative.
/// Shebang detection (see `has_shebang`) is the ultimate escape hatch for
/// anything not listed here.
fn has_code_extension(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".sh")
        || lower.ends_with(".bash")
        || lower.ends_with(".py")
        || lower.ends_with(".py3")
        || lower.ends_with(".rb")
        || lower.ends_with(".pl")
        || lower.ends_with(".js")
        || lower.ends_with(".ts")
        || lower.ends_with(".c")
        || lower.ends_with(".cc")
        || lower.ends_with(".cpp")
        || lower.ends_with(".rs")
        || lower.ends_with(".go")
        || lower.ends_with(".java")
        || lower.ends_with(".kt")
        || lower.ends_with(".swift")
        || lower.ends_with(".lua")
        || lower.ends_with(".r")
        || lower.ends_with(".php")
}

/// Returns true if the first line of the content is a shebang (`#!`).
/// Used both for +x permission in the workspace and for dispatch decisions.
fn has_shebang(content: &str) -> bool {
    content
        .lines()
        .next()
        .is_some_and(|first| first.starts_with("#!"))
}

/// Very lightweight content-based heuristic for smarter dispatch / error messages.
/// Used especially in oneshot mode for compiled languages.
#[allow(dead_code)]
fn looks_like_rust(content: &str) -> bool {
    content.contains("fn main(")
        || content.contains("#[tokio::main]")
        || content.contains("use std::")
}

#[allow(dead_code)]
fn looks_like_c_or_cpp(content: &str) -> bool {
    content.contains("#include <") || content.contains("int main(") || content.contains("std::")
}

/// Given an object name and its content, return the shell command
/// that should be used to execute it, if any.
///
/// Smarter heuristics (2025 iteration):
/// - Shebang always wins (author intent).
/// - For interpreted languages: simple direct invocation.
/// - For compiled languages: return a **self-contained** wrapper that
///   compiles into a private temp location, executes, and cleans up.
///   This makes `l2 exec hello.rs` and `l2 exec hello.c` "just work" in oneshot.
///
/// All commands are designed to be safe to pass to `sh -c` inside the sandbox.
fn compute_dispatch_command(name: &str, content: &str) -> Option<String> {
    if has_shebang(content) {
        return Some(format!("./{}", name));
    }

    let lower = name.to_ascii_lowercase();

    // Interpreted languages - direct execution
    if lower.ends_with(".py") || lower.ends_with(".py3") {
        return Some(format!("python3 {}", name));
    }
    if lower.ends_with(".sh") || lower.ends_with(".bash") {
        return Some(format!("sh {}", name));
    }
    if lower.ends_with(".rb") {
        return Some(format!("ruby {}", name));
    }
    if lower.ends_with(".pl") || lower.ends_with(".pm") {
        return Some(format!("perl {}", name));
    }
    if lower.ends_with(".js") {
        return Some(format!("node {}", name));
    }
    if lower.ends_with(".ts") {
        // Prefer deno if available, otherwise ts-node. Fall back gracefully.
        return Some(format!("sh -c 'command -v deno >/dev/null && deno run --allow-all \"{0}\" || npx --yes tsx \"{0}\"'", name));
    }
    if lower.ends_with(".lua") {
        return Some(format!("lua {}", name));
    }
    if lower.ends_with(".php") {
        return Some(format!("php {}", name));
    }
    if lower.ends_with(".go") {
        // Go single-file is nice with `go run`
        return Some(format!("go run {}", name));
    }

    // === Compiled languages - self-contained compile + run + cleanup ===
    // These are critical for good oneshot UX with C, Rust, C++, etc.
    if lower.ends_with(".c") {
        // Use a private temp dir that is cleaned even on failure
        return Some(format!(
            "sh -c 'mkdir -p .l2tmp && cc \"$1\" -o .l2tmp/_bin && .l2tmp/_bin; rc=$?; rm -rf .l2tmp; exit $rc' -- {}",
            name
        ));
    }
    if lower.ends_with(".cc") || lower.ends_with(".cpp") || lower.ends_with(".cxx") {
        return Some(format!(
            "sh -c 'mkdir -p .l2tmp && c++ \"$1\" -o .l2tmp/_bin && .l2tmp/_bin; rc=$?; rm -rf .l2tmp; exit $rc' -- {}",
            name
        ));
    }
    if lower.ends_with(".rs") {
        return Some(format!(
            "sh -c 'mkdir -p .l2tmp && rustc \"$1\" -o .l2tmp/_bin && .l2tmp/_bin; rc=$?; rm -rf .l2tmp; exit $rc' -- {}",
            name
        ));
    }

    None
}

/// Normalizes the flexible `exec` arguments into a usable form.
///
/// Returns (sys, effective_what, is_oneshot, policy_override).
///
/// Rules (see design doc for full disambiguation table):
/// - 0 args → error (clap should have caught)
/// - 1 arg:
///     - If it names an existing system → error "what is required"
///     - Else if it looks like a local file with code/shebang → oneshot
///     - Otherwise → treat as what with no sys (will fail later with good message)
/// - 2+ args → first is sys name, remainder joined by space is the command (or bare name for dispatch)
fn normalize_exec_args(args: &[String]) -> (Option<String>, String, bool, Option<String>) {
    if args.is_empty() {
        return (None, String::new(), false, None);
    }

    if args.len() == 1 {
        let candidate = &args[0];

        // Cheap check: does this name an existing system?
        // (We don't have state here easily, so we do a best-effort later in the handler.
        // For now we treat 1-arg as potential oneshot if it looks like a local code file.)
        let path = std::path::Path::new(candidate);
        if path.exists()
            && (has_code_extension(candidate) || {
                // Peek the file for shebang without loading everything
                std::fs::read_to_string(candidate)
                    .map(|c| has_shebang(&c))
                    .unwrap_or(false)
            })
        {
            return (None, candidate.clone(), true, None);
        }

        // Not a local code file → probably user meant a system but forgot the command
        (None, candidate.clone(), false, None)
    } else {
        let sys = args[0].clone();
        // Join the rest. This works for most cases because the shell already
        // handled the user's original quoting when they wrote `l2 exec sys 'cat "file with space"'`.
        let what = args[1..].join(" ");
        (Some(sys), what, false, None)
    }
}

fn state_path() -> PathBuf {
    data_dir().join("state.json")
}

fn load_state() -> Substrate {
    let path = state_path();
    if !path.exists() {
        return Substrate::default();
    }
    match fs::read_to_string(&path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(_) => Substrate::default(),
    }
}

fn save_state(sub: &Substrate) -> Result<()> {
    let dir = data_dir();
    fs::create_dir_all(&dir)?;
    let path = state_path();
    let json = serde_json::to_string_pretty(sub)?;
    fs::write(path, json)?;
    Ok(())
}

fn object_relative_path(name: &str) -> Result<PathBuf> {
    if name.is_empty() || name.contains('\0') {
        anyhow::bail!("object name must be a non-empty relative path");
    }

    let mut relative = PathBuf::new();
    for component in Path::new(name).components() {
        match component {
            Component::Normal(part) => relative.push(part),
            Component::CurDir => {}
            _ => anyhow::bail!(
                "object name '{}' must stay inside the system workspace",
                name
            ),
        }
    }

    if relative.as_os_str().is_empty() {
        anyhow::bail!("object name must name a file inside the system workspace");
    }

    Ok(relative)
}

fn object_workspace_path(workspace: &Path, name: &str) -> Result<PathBuf> {
    Ok(workspace.join(object_relative_path(name)?))
}

fn workspace_dir(sys: &System) -> Result<PathBuf> {
    if sys.id.is_empty()
        || !sys
            .id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        anyhow::bail!("system '{}' has an invalid stored id", sys.name);
    }

    Ok(std::env::temp_dir().join(format!("l2-ws-{}", sys.id)))
}

fn prepare_workspace(sys: &System) -> Result<PathBuf> {
    let ws = workspace_dir(sys)?;
    let _ = fs::remove_dir_all(&ws);
    fs::create_dir_all(&ws)?;

    for (name, obj) in &sys.objects {
        let path = object_workspace_path(&ws, name)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, &obj.content)?;

        // Shebang support (key part of "all the way" language execution on the host).
        // If the author put a proper shebang, make the file directly executable
        // inside the workspace so `./name` and bare-name dispatch work naturally.
        // This is harmless for data objects and is confined to the per-system ws.
        if has_shebang(&obj.content) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = fs::metadata(&path) {
                    let mut perms = meta.permissions();
                    perms.set_mode(0o755);
                    let _ = fs::set_permissions(&path, perms);
                }
            }
        }
    }
    Ok(ws)
}

impl Substrate {
    fn create(&mut self, name: &str, policy: &str) -> Result<String> {
        if self.systems.values().any(|s| s.name == name) {
            anyhow::bail!("system '{}' already exists", name);
        }
        let id = format!("sys-{:x}", self.next_id);
        self.next_id += 1;

        let sys = System {
            id: id.clone(),
            name: name.to_string(),
            policy: policy.to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            objects: HashMap::new(),
            grants: vec![],
        };
        self.systems.insert(id.clone(), sys);
        Ok(id)
    }

    fn destroy(&mut self, name: &str) -> Result<()> {
        let id = self.resolve_name(name)?;
        self.systems.remove(&id);
        Ok(())
    }

    fn list_systems(&self) -> Vec<&System> {
        self.systems.values().collect()
    }

    fn get_system(&self, name: &str) -> Result<&System> {
        let id = self.resolve_name(name)?;
        Ok(self.systems.get(&id).unwrap())
    }

    fn put(&mut self, sys_name: &str, obj_name: &str, typ: &str, content: &str) -> Result<()> {
        object_relative_path(obj_name)?;
        let id = self.resolve_name(sys_name)?;
        let sys = self.systems.get_mut(&id).unwrap();
        let obj = Object {
            name: obj_name.to_string(),
            r#type: typ.to_string(),
            content: content.to_string(),
            size: content.len(),
        };
        sys.objects.insert(obj_name.to_string(), obj);
        Ok(())
    }

    fn get(&self, sys_name: &str, obj_name: &str) -> Result<Object> {
        let id = self.resolve_name(sys_name)?;
        let sys = self.systems.get(&id).unwrap();
        sys.objects
            .get(obj_name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("object '{}' not found", obj_name))
    }

    fn resolve_name(&self, name: &str) -> Result<String> {
        for (id, sys) in &self.systems {
            if sys.name == name || id == name {
                return Ok(id.clone());
            }
        }
        anyhow::bail!(
            "system '{}' not found (data dir: {})",
            name,
            data_dir().display()
        );
    }
}

fn exec_isolated(
    what: &str,
    _input: Option<&str>,
    sys_name: &str,
    workspace: Option<PathBuf>,
) -> Result<String> {
    let mut cmd = Command::new("unshare");
    cmd.args(["--fork", "--pid", "--mount-proc", "--net", "sh", "-c", what]);

    if let Some(ws) = &workspace {
        cmd.current_dir(ws);
    }

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd.output()?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        let mut msg = format!(
            "[isolated exec in '{}'] failed (code {:?})\n",
            sys_name,
            output.status.code()
        );
        if !stdout.trim().is_empty() {
            msg.push_str(&format!("stdout:\n{}\n", stdout));
        }
        if !stderr.trim().is_empty() {
            msg.push_str(&format!("stderr:\n{}\n", stderr));
        }

        if stderr.contains("Operation not permitted") || stderr.contains("unshare failed") {
            msg.push_str(
                "\nHint: unshare(1) requires privileges or kernel support for user namespaces.\n",
            );
            msg.push_str(
                "      (l2 auto-escalates via sudo for exec; ensure sudo works for your user.)\n",
            );
        }
        return Ok(msg);
    }

    Ok(format!(
        "[isolated via unshare in '{}']\n{}",
        sys_name, stdout
    ))
}

fn print_json<T: Serialize>(value: &T) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("serializing CLI JSON output")
    );
}

fn json_line<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("serializing CLI JSON line")
}

fn success_json(msg: &str) -> serde_json::Value {
    serde_json::json!({"ok": true, "msg": msg})
}

fn error_json(msg: &str) -> serde_json::Value {
    serde_json::json!({"ok": false, "err": msg})
}

fn success(msg: &str, json: bool) {
    if json {
        println!("{}", json_line(&success_json(msg)));
    } else {
        println!("{} {}", "✓".green(), msg);
    }
}

fn error(msg: &str, json: bool) -> ! {
    if json {
        eprintln!("{}", json_line(&error_json(msg)));
    } else {
        eprintln!("{} {}", "✗".red(), msg);
    }
    std::process::exit(1);
}

fn sel4_setup() -> Result<()> {
    println!("🔧 Running seL4 setup...");
    // Resolve script relative to current working dir or CARGO_MANIFEST_DIR for dev
    let script = std::env::var("CARGO_MANIFEST_DIR")
        .map(|d| format!("{}/scripts/sel4-setup.sh", d))
        .unwrap_or_else(|_| "scripts/sel4-setup.sh".to_string());
    let status = Command::new("sh").arg(&script).status()?;
    if !status.success() {
        anyhow::bail!("seL4 setup failed (see script output)");
    }
    println!("✅ seL4 environment setup complete!");
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut sub = load_state();

    match cli.command {
        Commands::Create { name, policy } => match sub.create(&name, &policy) {
            Ok(id) => {
                save_state(&sub)?;
                if cli.json {
                    print_json(
                        &serde_json::json!({"ok":true,"sys":id,"name":name,"policy":policy}),
                    );
                } else {
                    println!(
                        "{} created system '{}' (id={})",
                        "✓".green(),
                        name.bold(),
                        id
                    );
                    println!("   policy: {}", policy);
                    println!("   state:  {}", state_path().display());
                }
            }
            Err(e) => error(&e.to_string(), cli.json),
        },
        Commands::Destroy { name } => {
            if let Err(e) = sub.destroy(&name) {
                error(&e.to_string(), cli.json);
            }
            let _ = save_state(&sub);
            success(&format!("destroyed '{}'", name), cli.json);
        }
        Commands::List { name } => {
            if let Some(sys_name) = name {
                match sub.get_system(&sys_name) {
                    Ok(sys) => {
                        if cli.json {
                            print_json(sys);
                        } else {
                            println!("System: {} ({})", sys.name.bold(), sys.id);
                            println!("  policy:   {}", sys.policy);
                            println!("  objects:");
                            if sys.objects.is_empty() {
                                println!("    (none)");
                            } else {
                                for (k, v) in &sys.objects {
                                    println!("    {} [{}] ({} bytes)", k, v.r#type, v.size);
                                }
                            }
                        }
                    }
                    Err(e) => error(&e.to_string(), cli.json),
                }
            } else {
                let systems = sub.list_systems();
                if cli.json {
                    print_json(&systems);
                } else if systems.is_empty() {
                    println!("No active systems.");
                    println!("Data dir: {}", data_dir().display());
                } else {
                    println!("Active systems:");
                    for s in systems {
                        println!(
                            "  {}  {}  ({} objects)",
                            s.id,
                            s.name.bold(),
                            s.objects.len()
                        );
                    }
                }
            }
        }
        Commands::Put {
            sys,
            name,
            r#type,
            content,
        } => {
            let data = content.unwrap_or_default();
            if let Err(e) = sub.put(&sys, &name, &r#type, &data) {
                error(&e.to_string(), cli.json);
            }
            let _ = save_state(&sub);
            success(&format!("put '{}' into '{}'", name, sys), cli.json);
        }
        Commands::Get { sys, name } => match sub.get(&sys, &name) {
            Ok(obj) => {
                if cli.json {
                    print_json(&obj);
                } else {
                    println!("Object: {}", obj.name.bold());
                    println!("Type:   {}", obj.r#type);
                    println!("Size:   {} bytes", obj.size);
                    println!("---");
                    println!("{}", obj.content);
                }
            }
            Err(e) => error(&e.to_string(), cli.json),
        },
        Commands::Exec {
            policy,
            args,
            input,
        } => {
            let (opt_sys, what, is_oneshot, pol_override) = normalize_exec_args(&args);

            if is_oneshot {
                // =====================================================
                // ONESHOT MODE: l2 exec hello.py   (or hello.c, etc.)
                // =====================================================
                let local_path = &what;

                if !is_privileged() {
                    // Cheap pre-check already passed in normalize (file existed + looked like code).
                    // Print a clear notice before we potentially ask for sudo.
                    eprintln!(
                        "{} {} {} one-shot execution of local file '{}'",
                        l2_prefix(),
                        oneshot_prefix(),
                        "→".cyan().bold(),
                        local_path.bold()
                    );
                    eprintln!(
                        "    {} temporary isolated system will be created and destroyed",
                        "→".dimmed()
                    );
                    escalate_to_root_for_exec(); // never returns
                }

                // We are now in a privileged context (either started that way or after sudo child).
                // Safe to read the local file and mutate state.
                let content = match std::fs::read_to_string(local_path) {
                    Ok(c) => c,
                    Err(e) => error(
                        &format!("failed to read oneshot file '{}': {}", local_path, e),
                        cli.json,
                    ),
                };

                if content.trim().is_empty() {
                    error(&format!("oneshot file '{}' is empty", local_path), cli.json);
                }

                let base_name = std::path::Path::new(local_path)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("script");

                // Temporary system name (visible for audit)
                let oneshot_id = format!("_oneshot_{:x}", std::process::id());
                let effective_policy = pol_override
                    .or_else(|| policy.clone())
                    .unwrap_or_else(|| "strict".to_string());

                // Create + populate the temporary system (only in privileged context)
                let _ = sub.create(&oneshot_id, &effective_policy);
                let _ = sub.put(&oneshot_id, base_name, "code", &content);
                let _ = save_state(&sub);

                let system = match sub.get_system(&oneshot_id) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = sub.destroy(&oneshot_id);
                        let _ = save_state(&sub);
                        error(
                            &format!("failed to prepare oneshot system: {}", e),
                            cli.json,
                        );
                    }
                };

                let ws_id_for_cleanup = system.id.clone();

                // Compute the effective command (shebang or dispatch table)
                let effective_what = compute_dispatch_command(base_name, &content)
                    .unwrap_or_else(|| format!("sh {}", base_name));

                if !cli.json {
                    eprintln!(
                        "{} {} {}  {}  {}",
                        oneshot_prefix(),
                        dispatch_prefix(),
                        base_name.bold(),
                        "→".cyan(),
                        effective_what.green()
                    );
                }

                let workspace = match prepare_workspace(system) {
                    Ok(ws) => Some(ws),
                    Err(e) => {
                        eprintln!("Warning: could not prepare oneshot workspace: {}", e);
                        None
                    }
                };

                if system.policy == "strict" {
                    let _ = sandbox::apply_strict_sandbox(workspace.as_deref());
                }

                let out = match exec_isolated(
                    &effective_what,
                    input.as_deref(),
                    &oneshot_id,
                    workspace,
                ) {
                    Ok(o) => o,
                    Err(e) => {
                        let _ = sub.destroy(&oneshot_id);
                        let _ = save_state(&sub);

                        let err_str = e.to_string();

                        // Special handling for compiled languages in oneshot
                        let lp_lower = local_path.to_ascii_lowercase();
                        if lp_lower.ends_with(".rs")
                            || lp_lower.ends_with(".c")
                            || lp_lower.ends_with(".cpp")
                            || lp_lower.ends_with(".cc")
                        {
                            error(
                                &format!(
                                    "oneshot compiled execution failed for '{}'\n\
                                     Common causes:\n\
                                       • No compiler in the chosen policy (try --policy default)\n\
                                       • Compilation error (see output above)\n\
                                       • Missing dependencies\n\n\
                                     Tip: Use a shebang or explicit command for full control:\n\
                                       l2 exec --policy default {} 'rustc {} -o /tmp/a && /tmp/a'",
                                    local_path, local_path, base_name
                                ),
                                cli.json,
                            );
                        }

                        // General interpreter/policy hint
                        if err_str.contains("not found") || err_str.contains("No such file") {
                            error(
                                &format!(
                                    "oneshot execution failed: interpreter for '{}' may not be allowed by policy '{}'\n\
                                     Try: l2 exec --policy default {}  (or use a shebang in your file)",
                                    effective_what, effective_policy, local_path
                                ),
                                cli.json,
                            );
                        }
                        error(&err_str, cli.json);
                    }
                };

                // Always destroy the temporary system (after we're done using the borrow)
                let _ = sub.destroy(&oneshot_id);
                let _ = save_state(&sub);
                // Best-effort workspace cleanup
                let _ = std::fs::remove_dir_all(
                    std::env::temp_dir().join(format!("l2-ws-{}", ws_id_for_cleanup)),
                );

                if !cli.json {
                    println!(
                        "{} {} {} created temporary system '{}'  {} executed  {} destroyed",
                        "✓".green().bold(),
                        l2_prefix(),
                        oneshot_prefix(),
                        oneshot_id.dimmed(),
                        "→".cyan(),
                        "→".cyan()
                    );
                }

                if cli.json {
                    print_json(&serde_json::json!({"ok": true, "output": out}));
                } else {
                    println!("{}", out);
                }

                return Ok(()); // important: we handled cleanup
            }

            // =====================================================
            // NORMAL (named system) MODE
            // =====================================================
            let sys = match opt_sys {
                Some(s) => s,
                None => error(
                    "system name required (or use one-shot mode with a local code file)",
                    cli.json,
                ),
            };

            let mut effective_what = what.clone();

            // Try to auto-dispatch bare names that match code objects we already have
            if let Ok(system) = sub.get_system(&sys) {
                if let Some(obj) = system.objects.get(&what) {
                    if let Some(dispatched) = compute_dispatch_command(&what, &obj.content) {
                        effective_what = dispatched;
                        if !cli.json {
                            eprintln!(
                                "{} {}  {}  {}",
                                dispatch_prefix(),
                                what.bold(),
                                "→".cyan(),
                                effective_what.green()
                            );
                        }
                    }
                }

                // Existing friendly validation (now using the possibly-dispatched what)
                validate_exec_target_references_real_object(
                    &effective_what,
                    system,
                    &sys,
                    cli.json,
                );
            }

            // Privilege escalation (unchanged behavior for named systems)
            if !is_privileged() {
                escalate_to_root_for_exec();
            }

            let system = sub.get_system(&sys)?;

            let workspace = match prepare_workspace(system) {
                Ok(ws) => Some(ws),
                Err(e) => {
                    eprintln!("Warning: could not prepare workspace: {}", e);
                    None
                }
            };

            if system.policy == "strict" {
                let _ = sandbox::apply_strict_sandbox(workspace.as_deref());
            }

            match exec_isolated(&effective_what, input.as_deref(), &sys, workspace) {
                Ok(out) => {
                    let mut to_print = out;

                    if !cli.json
                        && !system.objects.is_empty()
                        && (to_print.contains("No such file or directory")
                            || to_print.contains("code Some(127)")
                            || to_print.contains("not found"))
                    {
                        if !to_print.ends_with('\n') {
                            to_print.push('\n');
                        }
                        to_print.push_str(&format!(
                            "(system '{}' contains these objects: {})\n",
                            sys,
                            list_available_objects(system)
                        ));
                        if let Some(cmd) = suggest_working_command(system) {
                            to_print.push_str(&format!(" Try: l2 exec {} '{}'\n", sys, cmd));
                        }
                    }

                    if cli.json {
                        print_json(&serde_json::json!({"ok": true, "output": to_print}));
                    } else {
                        println!("{}", to_print);
                    }
                }
                Err(e) => error(&e.to_string(), cli.json),
            }
        }
        Commands::Revoke { sys, grant } => success(
            &format!("revoked '{}' from '{}' (prototype)", grant, sys),
            cli.json,
        ),
        Commands::Status { name } => {
            if let Some(n) = name {
                match sub.get_system(&n) {
                    Ok(sys) => {
                        if cli.json {
                            print_json(sys);
                        } else {
                            println!("System {} policy={}", sys.name, sys.policy);
                        }
                    }
                    Err(e) => error(&e.to_string(), cli.json),
                }
            } else {
                let count = sub.systems.len();
                if cli.json {
                    print_json(&serde_json::json!({"systems": count}));
                } else {
                    println!("l2 host prototype (persistent)");
                    println!("  active systems: {}", count);
                    println!("  data dir:       {}", data_dir().display());
                }
            }
        }
        Commands::Sel4Setup => {
            sel4_setup()?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_json_escapes_message_text() {
        let msg = "put 'name\"with\\chars\nline' into 'sys'";
        let line = json_line(&success_json(msg));
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();

        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["msg"], msg);
    }

    #[test]
    fn error_json_escapes_error_text() {
        let msg = "system 'bad\"name' not found: path C:\\tmp";
        let line = json_line(&error_json(msg));
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();

        assert_eq!(parsed["ok"], false);
        assert_eq!(parsed["err"], msg);
    }

    #[test]
    fn object_paths_allow_nested_relative_names() {
        let path = object_workspace_path(Path::new("/tmp/l2-workspace"), "./src/main.rs").unwrap();

        assert_eq!(path, PathBuf::from("/tmp/l2-workspace/src/main.rs"));
    }

    #[test]
    fn object_paths_reject_workspace_escape_names() {
        assert!(object_workspace_path(Path::new("/tmp/l2-workspace"), "../escape").is_err());
        assert!(object_workspace_path(Path::new("/tmp/l2-workspace"), "/tmp/escape").is_err());
        assert!(object_workspace_path(Path::new("/tmp/l2-workspace"), ".").is_err());
    }

    #[test]
    fn put_rejects_unsafe_object_names_before_state_changes() {
        let mut sub = Substrate::default();
        sub.create("sys", "strict").unwrap();

        assert!(sub.put("sys", "../escape", "data", "nope").is_err());
        assert!(sub.get_system("sys").unwrap().objects.is_empty());
    }

    #[test]
    fn strict_sandbox_applies_without_error() {
        // Exercises the new v0.2.0 Landlock + no_new_privs path.
        // Must succeed (even if kernel only partially enforces Landlock in the test env).
        let tmp = std::env::temp_dir().join(format!("l2-smoke-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let res = sandbox::apply_strict_sandbox(Some(&tmp));
        assert!(res.is_ok(), "sandbox apply failed: {:?}", res.err());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // --- Dispatch / language execution helpers (supporting "all the way" + shebang) ---

    #[test]
    fn has_code_extension_recognizes_common_sources() {
        assert!(has_code_extension("foo.py"));
        assert!(has_code_extension("bar.rs"));
        assert!(has_code_extension("script.sh"));
        assert!(has_code_extension("main.c"));
        assert!(has_code_extension("app.js"));
        assert!(!has_code_extension("README.md"));
        assert!(!has_code_extension("binary"));
    }

    #[test]
    fn has_shebang_detects_proper_shebangs() {
        assert!(has_shebang("#!/usr/bin/env python3\nprint('hi')"));
        assert!(has_shebang("#!/bin/sh\necho hi"));
        assert!(!has_shebang("just some text"));
        assert!(!has_shebang(""));
    }

    #[test]
    fn compute_dispatch_prefers_shebang() {
        let content = "#!/usr/bin/env python3\nprint('hello')";
        assert_eq!(
            compute_dispatch_command("task.py", content),
            Some("./task.py".to_string())
        );
    }

    #[test]
    fn compute_dispatch_falls_back_to_curated_table() {
        assert_eq!(
            compute_dispatch_command("foo.py", "print(1)"),
            Some("python3 foo.py".to_string())
        );
        assert_eq!(
            compute_dispatch_command("bar.sh", "echo hi"),
            Some("sh bar.sh".to_string())
        );
        assert_eq!(
            compute_dispatch_command("app.js", "console.log(1)"),
            Some("node app.js".to_string())
        );
        assert_eq!(compute_dispatch_command("weird.xyz", "data"), None);
    }
}
