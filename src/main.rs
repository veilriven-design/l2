//! l2 - Focused Latticra substrate (host prototype with persistence)
//!
//! State lives in ~/.l2/state.json (override with L2_DATA_DIR).
//!
//! When run under sudo, it automatically uses the original user's home directory.
//!
//! NOTE (architecture prep): Full split to thin CLI + out-of-process l2-core (L2P over stdio)
//! is in progress. See host/core.rs (now has basic L2P handler) and docs/PROTOCOL.md.

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use serde::Serialize;
use std::path::PathBuf;
use std::process::{Command, Stdio};
mod audit;
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
        /// Policy protocol to use.
        /// Examples: "strict", "strict-mcp" (current main focus), "default".
        /// These protocols make the isolation and hardening guarantees explicit.
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
    Sel4Setup {
        /// Disable slow/paced terminal output (useful on old/slow hardware or in scripts/CI)
        #[arg(long, short = 'f')]
        fast: bool,
    },

    /// Run a command with seccomp tracing enabled (Phase 1 allowlist collection).
    ///
    /// Companion to `l2 harden` (the host/environment hardening tool).
    /// Use this to safely collect data while exercising policy protocols
    /// such as "strict-mcp" (current main focus for high-assurance agentic/MCP work).
    Trace {
        /// Run inside an existing system instead of oneshot mode
        #[arg(short, long)]
        system: Option<String>,

        /// Command and arguments to execute under trace mode.
        /// Not required when using --analyze.
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,

        #[arg(long)]
        input: Option<String>,

        /// Policy protocol to use.
        /// Examples: "strict", "strict-mcp", "strict-audit".
        /// These define the exact isolation and hardening guarantees applied.
        #[arg(long, default_value = "strict")]
        policy: String,

        /// Enable Phase 1 seccomp enforcing filter (kills process on disallowed syscalls).
        /// This is strong true hardening on top of the chosen policy protocol.
        #[arg(long)]
        enforce: bool,

        /// Analyze a previously captured log (dmesg/journalctl/ausearch style)
        /// and print unique syscall numbers. Great for Phase 1 allowlist work.
        #[arg(long)]
        analyze: Option<String>,
    },

    /// Apply high-assurance hardening to the current system (host, container, or environment)
    /// aligned with NSA/CISA/FBI guidance for the agentic/AI/MCP era.
    ///
    /// This is the companion to policy protocols like "strict-mcp".
    /// Running `l2 harden` prepares the substrate environment so that `strict-mcp`
    /// (and future hardened protocols) can be used safely and effectively.
    Harden {
        /// Hardening level / profile.
        /// "strict-mcp" is the current recommended profile for agentic/MCP workloads.
        #[arg(long, default_value = "strict-mcp")]
        profile: String,

        /// Target scope: "host", "container", or "user".
        #[arg(long, default_value = "host")]
        target: String,

        /// Dry-run: show what would be done without making changes.
        #[arg(long)]
        dry_run: bool,

        /// Disable paced/slow output (useful in CI or on old hardware).
        #[arg(long, short = 'f')]
        fast: bool,

        /// Enable strong network isolation recommendations/lockdown for the agent user.
        /// One of the highest value controls for MCP/agent workloads.
        #[arg(long)]
        network_isolation: bool,

        /// Generate a minimal real seccomp profile from a trace previously collected with
        /// `l2 trace --policy strict-mcp ...`. Produces both systemd SystemCallFilter
        /// and data suitable for our custom Phase 1 enforcing filter.
        #[arg(long)]
        generate_seccomp: Option<String>,
    },

    /// List available policy protocols (strict, strict-mcp, etc.)
    Policies {},

    /// Show details for a specific policy protocol
    Policy {
        /// Name of the policy protocol (e.g. "strict-mcp")
        name: String,

        /// Show in JSON format
        #[arg(long)]
        json: bool,
    },

    /// View or manage the authority audit log (append-only JSONL)
    Audit {
        /// Show the last N entries
        #[arg(long, default_value_t = 50)]
        tail: usize,

        /// Output raw JSONL instead of human-readable
        #[arg(long)]
        json: bool,

        /// Just print the path to the audit log and exit
        #[arg(long)]
        path: bool,
    },
}

// Core types now live in the library (src/lib.rs) for the architecture split prep.
// The CLI re-uses them via `l2::...`.
use l2::{
    data_dir, load_state, prepare_workspace, save_state, state_path, warn_on_cleanup_err, System,
};

// Core helpers now come from the library (see src/lib.rs) as part of architecture prep.

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

    audit::log(
        "escalate",
        serde_json::json!({
            "exe": exe.display().to_string(),
            "args": args
        }),
    );

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

// warn_on_cleanup_err is now provided by the l2 library (see src/lib.rs for the shared implementation).

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

/// Known policy protocols.
/// These are explicit "policy protocols" the user chooses. They determine
/// isolation guarantees and hardening behavior (Landlock rules, seccomp, etc.).
///
/// Current protocols:
/// - "default": pragmatic balance
/// - "strict": strong isolation + seccomp (Landlock + no_new_privs + observer/enforcing)
/// - "strict-mcp": **current main focus** — strict + MCP/agent-specific hardening:
///     * Stronger seccomp enforcement by default
///     * No ambient network by default for MCP tool execution
///     * Tighter capability and filesystem posture suitable for tool-using agents
///     * Clear audit of "MCP workload" context
fn normalize_policy(policy: &str) -> (String, bool, bool) {
    match policy {
        "strict-mcp" => {
            // strict-mcp is our primary hardened protocol for agentic/MCP workloads.
            // It implies stricter defaults than plain "strict".
            (policy.to_string(), true, true) // (name, is_strict_family, is_mcp)
        }
        "strict" => {
            (policy.to_string(), true, false)
        }
        "default" | _ => (policy.to_string(), false, false),
    }
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

// state_path, load_state, save_state now from l2:: (library)

// object_relative_path, object_workspace_path, workspace_dir, prepare_workspace
// now provided by the l2 library (src/lib.rs) for the core split.

// Substrate impl now lives in the library (src/lib.rs) as part of architecture prep for the core split.
// The methods are pub there.

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
    match serde_json::to_string_pretty(value) {
        Ok(s) => println!("{}", s),
        Err(e) => {
            eprintln!("warning: failed to serialize JSON output: {}", e);
            // Fallback to a minimal error object so scripts don't break completely
            println!(r#"{{"ok":false,"err":"internal serialization failure"}}"#);
        }
    }
}

fn json_line<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|e| {
        // Extremely unlikely for our controlled types; fall back gracefully
        format!(r#"{{"ok":false,"err":"serialization error: {}"}}"#, e)
    })
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

fn sel4_setup(fast: bool) -> Result<()> {
    println!("🔧 Running seL4 setup...");
    // Resolve script relative to current working dir or CARGO_MANIFEST_DIR for dev
    let script = std::env::var("CARGO_MANIFEST_DIR")
        .map(|d| format!("{}/scripts/sel4-setup.sh", d))
        .unwrap_or_else(|_| "scripts/sel4-setup.sh".to_string());

    let mut cmd = Command::new("sh");
    cmd.arg(&script);

    if fast {
        cmd.arg("--fast");
        cmd.env("L2_FAST", "1");
    }

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("seL4 setup failed (see script output)");
    }
    println!("✅ seL4 environment setup complete!");
    Ok(())
}

/// High-assurance system hardening for the agentic/AI/MCP era.
/// Companion to policy protocols such as "strict-mcp".
fn harden(
    profile: String,
    target: String,
    dry_run: bool,
    fast: bool,
    network_isolation: bool,
    generate_seccomp: Option<String>,
) -> Result<()> {
    println!("🛡️  Running l2 system hardening...");
    println!("   Profile : {}", profile);
    println!("   Target  : {}", target);
    if dry_run {
        println!("   Mode    : DRY-RUN (no changes will be made)");
    }
    if network_isolation {
        println!("   Network isolation: ENABLED");
    }
    if let Some(trace) = &generate_seccomp {
        println!("   Generate seccomp profile from: {}", trace);
    }

    let script = std::env::var("CARGO_MANIFEST_DIR")
        .map(|d| format!("{}/scripts/harden.sh", d))
        .unwrap_or_else(|_| "scripts/harden.sh".to_string());

    let mut cmd = Command::new("sh");
    cmd.arg(&script);
    cmd.arg("--profile").arg(&profile);
    cmd.arg("--target").arg(&target);

    if dry_run {
        cmd.arg("--dry-run");
    }
    if fast {
        cmd.arg("--fast");
        cmd.env("L2_FAST", "1");
    }
    if network_isolation {
        cmd.arg("--network-isolation");
    }
    if let Some(trace) = &generate_seccomp {
        cmd.arg("--generate-seccomp").arg(trace);
    }

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("System hardening failed (see script output)");
    }

    println!("✅ l2 system hardening complete for profile '{}'.", profile);
    println!("   Review the generated report and apply any manual steps as needed.");
    println!();
    println!("   Recommended next step for this profile:");
    println!("     l2 trace --policy {} ./your-mcp-workload", profile);
    println!("     l2 exec  --policy {} ./your-mcp-workload", profile);
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut sub = load_state();

    match cli.command {
        Commands::Create { name, policy } => match sub.create(&name, &policy) {
            Ok(id) => {
                save_state(&sub)?;
                audit::log(
                    "create",
                    serde_json::json!({
                        "name": name,
                        "id": id,
                        "policy": policy
                    }),
                );
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
                    let sp = state_path()?;
                    println!("   state:  {}", sp.display());
                }
            }
            Err(e) => error(&e.to_string(), cli.json),
        },
        Commands::Destroy { name } => {
            if let Err(e) = sub.destroy(&name) {
                error(&e.to_string(), cli.json);
            }
            audit::log("destroy", serde_json::json!({ "name": name }));
            warn_on_cleanup_err(save_state(&sub), "failed to save state after destroy");
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
                    let dd = data_dir()?;
                    println!("Data dir: {}", dd.display());
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
            warn_on_cleanup_err(save_state(&sub), "failed to save state after put");
            audit::log(
                "put",
                serde_json::json!({
                    "sys": sys,
                    "name": name,
                    "type": r#type,
                    "size": data.len()
                }),
            );
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
                if let Err(e) = sub.create(&oneshot_id, &effective_policy) {
                    error(&format!("failed to create oneshot system: {}", e), cli.json);
                }
                audit::log(
                    "create",
                    serde_json::json!({
                        "name": oneshot_id,
                        "policy": effective_policy,
                        "oneshot": true
                    }),
                );
                warn_on_cleanup_err(
                    sub.put(&oneshot_id, base_name, "code", &content),
                    "failed to put oneshot content",
                );
                warn_on_cleanup_err(
                    save_state(&sub),
                    "failed to save state after oneshot create/put",
                );

                let system = match sub.get_system(&oneshot_id) {
                    Ok(s) => s,
                    Err(e) => {
                        warn_on_cleanup_err(
                            sub.destroy(&oneshot_id),
                            "failed to destroy oneshot system after prep failure",
                        );
                        warn_on_cleanup_err(
                            save_state(&sub),
                            "failed to save state after oneshot prep failure",
                        );
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

                let (_effective_policy, is_strict_family, is_mcp) = normalize_policy(&system.policy);
                if is_strict_family {
                    warn_on_cleanup_err(
                        sandbox::apply_strict_sandbox(workspace.as_deref(), &system.policy),
                        "strict sandbox apply reported error (non-fatal)",
                    );
                    sandbox::print_seccomp_trace_reminder();
                }
                if is_mcp {
                    // strict-mcp can get extra future restrictions here (e.g. network denial hints)
                }

                audit::log(
                    "exec",
                    serde_json::json!({
                        "sys": oneshot_id,
                        "what": effective_what,
                        "policy": effective_policy,
                        "oneshot": true,
                        "source_file": local_path
                    }),
                );

                let out = match exec_isolated(
                    &effective_what,
                    input.as_deref(),
                    &oneshot_id,
                    workspace,
                ) {
                    Ok(o) => o,
                    Err(e) => {
                        warn_on_cleanup_err(
                            sub.destroy(&oneshot_id),
                            "failed to destroy oneshot system on exec error",
                        );
                        warn_on_cleanup_err(
                            save_state(&sub),
                            "failed to save state during oneshot error recovery",
                        );

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
                warn_on_cleanup_err(sub.destroy(&oneshot_id), "failed to destroy oneshot system");
                warn_on_cleanup_err(
                    save_state(&sub),
                    "failed to save state after oneshot destroy",
                );
                // Best-effort workspace cleanup
                warn_on_cleanup_err(
                    std::fs::remove_dir_all(
                        std::env::temp_dir().join(format!("l2-ws-{}", ws_id_for_cleanup)),
                    ),
                    "failed to remove oneshot workspace",
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

            let (_effective_policy, is_strict_family, _is_mcp) = normalize_policy(&system.policy);
            if is_strict_family {
                warn_on_cleanup_err(
                    sandbox::apply_strict_sandbox(workspace.as_deref(), &system.policy),
                    "strict sandbox apply reported error (non-fatal)",
                );
                sandbox::print_seccomp_trace_reminder();
            }

            audit::log(
                "exec",
                serde_json::json!({
                    "sys": sys,
                    "what": effective_what,
                    "policy": system.policy,
                    "oneshot": false
                }),
            );

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
        Commands::Revoke { sys, grant } => {
            audit::log("revoke", serde_json::json!({ "sys": sys, "grant": grant }));
            success(
                &format!("revoked '{}' from '{}' (prototype)", grant, sys),
                cli.json,
            )
        }
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
                    let dd = data_dir()?;
                    println!("  data dir:       {}", dd.display());
                }
            }
        }
        Commands::Sel4Setup { fast } => {
            sel4_setup(fast)?;
        }

        Commands::Harden { profile, target, dry_run, fast, network_isolation, generate_seccomp } => {
            harden(profile, target, dry_run, fast, network_isolation, generate_seccomp)?;
        }

        Commands::Policies {} => {
            println!("Available policy protocols:\n");
            println!("  default     - Pragmatic balance (current default behavior)");
            println!("  strict      - Strong isolation + seccomp (Landlock + no_new_privs)");
            println!("  strict-mcp  - **Current main focus**");
            println!("                High-assurance protocol for agentic/AI/MCP workloads.");
            println!("                Builds on 'strict' with:");
            println!("                  • Stronger seccomp enforcing by default");
            println!("                  • MCP/tool-execution threat model considerations");
            println!("                  • Designed to pair with output from `l2 harden --profile strict-mcp`");
            println!("\nUse `l2 policy <name>` for detailed information (e.g. `l2 policy strict-mcp`).");
        }

        Commands::Policy { name, json } => {
            // Support both "l2 policy strict-mcp" and "l2 policy show strict-mcp"
            let name_lower = name.to_lowercase();
            if name_lower == "show" {
                // Re-parse next arg would be complex in this simple handler.
                // For now we document "l2 policy <name>" as the primary form.
                println!("Usage: l2 policy <name>");
                println!("Example: l2 policy strict-mcp");
                return Ok(());
            }

            match name_lower.as_str() {
                "strict-mcp" => {
                    if json {
                        let info = serde_json::json!({
                            "name": "strict-mcp",
                            "description": "High-assurance policy protocol for agentic, AI, and MCP (tool-using agent) workloads.",
                            "base": "strict",
                            "key_differences": [
                                "Enforcing seccomp enabled by default",
                                "Designed for workloads that invoke external tools/MCP servers",
                                "Pairs with host hardening produced by `l2 harden --profile strict-mcp`",
                                "Strong emphasis on least privilege for tool execution"
                            ],
                            "recommended_usage": "l2 exec --policy strict-mcp ...   and   l2 trace --policy strict-mcp ...",
                            "companion_command": "l2 harden --profile strict-mcp"
                        });
                        print_json(&info);
                    } else {
                        println!("strict-mcp — High-Assurance MCP/Agent Policy Protocol");
                        println!("======================================================");
                        println!();
                        println!("This is the current main focus of l2 hardening work.");
                        println!();
                        println!("Description:");
                        println!("  A strict-family policy protocol tailored for the agentic/AI/MCP era.");
                        println!("  It provides strong isolation while being practical for systems that");
                        println!("  dynamically invoke tools, MCP servers, and external processes.");
                        println!();
                        println!("Key characteristics:");
                        println!("  • Builds directly on the 'strict' isolation baseline");
                        println!("  • Phase 1 seccomp enforcing filter enabled by default");
                        println!("  • Designed to run on hosts/containers hardened by `l2 harden --profile strict-mcp`");
                        println!("  • Strong audit visibility of policy protocol in use");
                        println!();
                        println!("Recommended usage:");
                        println!("  l2 exec  --policy strict-mcp my-agent ./task");
                        println!("  l2 trace --policy strict-mcp ./my-mcp-server");
                        println!();
                        println!("Companion command:");
                        println!("  l2 harden --profile strict-mcp");
                        println!("    → Prepares your system with NSA/CISA/FBI-aligned controls for this workload class.");
                    }
                }
                "strict" => {
                    if json {
                        print_json(&serde_json::json!({
                            "name": "strict",
                            "description": "Strong isolation using Landlock + no_new_privs + seccomp.",
                            "base_for": ["strict-mcp"]
                        }));
                    } else {
                        println!("strict");
                        println!("------");
                        println!("Strong isolation policy using Landlock, no_new_privs, and seccomp.");
                        println!("This is the foundation that strict-mcp builds upon.");
                        println!("Use `l2 policy show strict-mcp` for the currently recommended protocol.");
                    }
                }
                other => {
                    if json {
                        print_json(&serde_json::json!({"name": other, "known": false}));
                    } else {
                        println!("Unknown policy protocol: {}", other);
                        println!("Known protocols: default, strict, strict-mcp");
                        println!("Run `l2 policies` to list them.");
                    }
                }
            }
        }

        Commands::Trace { system, command, input, policy, enforce, analyze } => {
            if let Some(logfile) = analyze {
                // Simple post-processing helper for Phase 1 (item 3)
                let content = std::fs::read_to_string(&logfile)
                    .unwrap_or_else(|_| String::new());

                let mut syscalls = std::collections::BTreeSet::new();

                for line in content.lines() {
                    if let Some(idx) = line.find("syscall=") {
                        if let Some(num_str) = line[idx+8..].split(|c: char| !c.is_ascii_digit()).next() {
                            if let Ok(n) = num_str.parse::<u32>() {
                                syscalls.insert(n);
                            }
                        }
                    }
                    if let Some(idx) = line.find(" nr=") {
                        if let Some(num_str) = line[idx+4..].split(|c: char| !c.is_ascii_digit()).next() {
                            if let Ok(n) = num_str.parse::<u32>() {
                                syscalls.insert(n);
                            }
                        }
                    }
                }

                if syscalls.is_empty() {
                    println!("No syscalls found in {}. Try: journalctl -k | grep seccomp > log.txt", logfile);
                } else {
                    println!("Unique syscalls found ({}):", syscalls.len());
                    println!();

                    // Expanded name map for curation (keep this in sync with allowlist doc)
                    let names: std::collections::HashMap<u32, &str> = [
                        (0, "read"), (1, "write"), (3, "close"), (8, "lseek"),
                        (9, "mmap"), (10, "mprotect"), (11, "munmap"), (12, "brk"),
                        (59, "execve"), (60, "exit"), (231, "exit_group"),
                        (257, "openat"), (78, "getdents64"), (228, "clock_gettime"),
                        (202, "futex"), (13, "rt_sigaction"), (14, "rt_sigprocmask"),
                        (79, "getcwd"), (435, "clone3"), (16, "ioctl"),
                        (270, "pselect6"), (262, "newfstatat"),
                    ].iter().cloned().collect();

                    println!("```");
                    for n in &syscalls {
                        if let Some(name) = names.get(n) {
                            println!("- {}   # {}", n, name);
                        } else {
                            println!("- {}   # UNKNOWN - investigate!", n);
                        }
                    }
                    println!("```");
                    println!();
                    println!("Copy the block above into docs/seccomp-phase1-allowlist.md under the relevant architecture section.");
                    println!("Then review each one for safety before adding to the enforcing filter.");
                }
                return Ok(());
            }

            // === Trace execution with explicit policy protocol awareness ===

            let (canonical_policy, _is_strict_family, is_mcp) = normalize_policy(&policy);

            // Always enable observer when tracing (for Phase 1 data collection)
            std::env::set_var("L2_STRICT_SECCOMP_OBSERVE", "1");

            // strict-mcp (main focus) + any strict family gets strong defaults.
            // We bias toward enabling the enforcing filter for these protocols.
            let should_enforce = enforce || is_mcp || canonical_policy.starts_with("strict");

            if should_enforce {
                std::env::set_var("L2_STRICT_SECCOMP_ENFORCE", "1");
            }

            let enforce_active = std::env::var_os("L2_STRICT_SECCOMP_ENFORCE").is_some();
            println!(
                "[trace] Starting with policy protocol: '{}'  |  observer=ON  |  enforce={}",
                canonical_policy,
                if enforce_active { "ON (Phase 1 true hardening)" } else { "OFF" }
            );

            match canonical_policy.as_str() {
                "strict-mcp" => {
                    println!(
                        "[trace] Using strict-mcp policy protocol — our current main focus.\n\
                         This protocol provides high-assurance hardened execution suitable for\n\
                         MCP servers and tools. Strong isolation + seccomp enforcing is active."
                    );
                }
                p if p.starts_with("strict") => {
                    println!("[trace] This policy protocol enables strong isolation + seccomp hardening.");
                }
                _ => {}
            }

            let mut child_args = vec!["exec".to_string(), "--policy".to_string(), canonical_policy.clone()];

            if let Some(i) = &input {
                child_args.push("--input".to_string());
                child_args.push(i.clone());
            }

            if let Some(s) = &system {
                child_args.push(s.clone());
            }
            child_args.extend(command.clone());

            let exe = std::env::current_exe()?;
            let status = std::process::Command::new(exe)
                .args(&child_args)
                .status()?;

            if !status.success() {
                std::process::exit(status.code().unwrap_or(1));
            }
        }

        Commands::Audit { tail, json, path } => {
            let log_path = audit::path();

            if path {
                println!("{}", log_path.display());
                return Ok(());
            }

            if !log_path.exists() {
                if json {
                    println!("[]");
                } else {
                    println!("No audit log yet at {}", log_path.display());
                    println!("Audit events are written for create/put/exec/destroy and privilege escalations.");
                }
                return Ok(());
            }

            let content = match std::fs::read_to_string(&log_path) {
                Ok(c) => c,
                Err(e) => error(&format!("failed to read audit log: {}", e), cli.json),
            };

            let lines: Vec<&str> = content.lines().collect();
            let start = if lines.len() > tail {
                lines.len() - tail
            } else {
                0
            };
            let selected = &lines[start..];

            if json {
                for line in selected {
                    println!("{}", line);
                }
            } else {
                println!("Audit log: {}", log_path.display());
                println!("Showing last {} entries:\n", selected.len());
                for line in selected {
                    // Try to pretty-print a bit
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                        let ts = v["ts"].as_str().unwrap_or("?");
                        let op = v["op"].as_str().unwrap_or("?");
                        println!("{}  {}  {}", ts, op.bright_blue().bold(), line);
                    } else {
                        println!("{}", line);
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2::{load_state, save_state, Substrate};
    use std::path::Path;

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
        let path =
            l2::object_workspace_path(Path::new("/tmp/l2-workspace"), "./src/main.rs").unwrap();

        assert_eq!(path, PathBuf::from("/tmp/l2-workspace/src/main.rs"));
    }

    #[test]
    fn object_paths_reject_workspace_escape_names() {
        assert!(l2::object_workspace_path(Path::new("/tmp/l2-workspace"), "../escape").is_err());
        assert!(l2::object_workspace_path(Path::new("/tmp/l2-workspace"), "/tmp/escape").is_err());
        assert!(l2::object_workspace_path(Path::new("/tmp/l2-workspace"), ".").is_err());
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
        // Exercises the v0.2 Landlock + no_new_privs path + the Phase 0 seccomp observer scaffolding
        // (when L2_STRICT_SECCOMP_OBSERVE=1). Must succeed in all envs.
        let tmp = std::env::temp_dir().join(format!("l2-smoke-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        // Enable observer for the test (purely additive, non-enforcing)
        std::env::set_var("L2_STRICT_SECCOMP_OBSERVE", "1");
        let res = sandbox::apply_strict_sandbox(Some(&tmp), "strict");
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

    #[test]
    fn warn_on_cleanup_err_does_not_panic_and_logs_on_error() {
        // Success path
        warn_on_cleanup_err::<std::io::Error>(Ok(()), "should not warn");

        // Error path (just exercises the eprintln path)
        warn_on_cleanup_err(Err("simulated cleanup failure"), "test cleanup");
    }

    #[test]
    fn data_dir_returns_error_when_home_missing() {
        // This test is best-effort; environment mutation is not perfectly isolated
        // but the error path is now properly returned instead of panicking.
        let original = std::env::var("HOME").ok();
        std::env::remove_var("HOME");
        // Also clear L2_DATA_DIR so we hit the HOME path
        let original_data = std::env::var("L2_DATA_DIR").ok();
        std::env::remove_var("L2_DATA_DIR");

        let result = data_dir();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("HOME environment variable"));

        // Restore
        if let Some(h) = original {
            std::env::set_var("HOME", h);
        }
        if let Some(d) = original_data {
            std::env::set_var("L2_DATA_DIR", d);
        }
    }

    #[test]
    fn data_dir_respects_l2_data_dir_override() {
        let temp = std::env::temp_dir().join(format!("l2-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp);
        std::env::set_var("L2_DATA_DIR", temp.to_str().unwrap());

        let dir = data_dir().expect("data_dir with override should succeed");
        assert_eq!(dir, temp);

        // Cleanup
        let _ = std::env::remove_var("L2_DATA_DIR");
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn json_helpers_do_not_panic_on_valid_data() {
        let val = success_json("test message");
        // Should not panic
        let _ = json_line(&val);
        // print_json writes to stdout, hard to assert here without capture, but call is safe
        print_json(&val);
    }

    #[test]
    fn audit_path_is_consistent_with_data_dir() {
        let temp = std::env::temp_dir().join(format!("l2-audit-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp);
        std::env::set_var("L2_DATA_DIR", temp.to_str().unwrap());

        let audit_p = audit::path();
        assert!(audit_p.ends_with("audit.log"));
        assert!(audit_p.parent().unwrap().ends_with(".l2") || audit_p.parent().unwrap() == temp); // depending on logic

        let _ = std::env::remove_var("L2_DATA_DIR");
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn load_state_handles_corrupt_json_gracefully() {
        let temp = std::env::temp_dir().join(format!("l2-corrupt-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp);
        std::env::set_var("L2_DATA_DIR", temp.to_str().unwrap());

        // Write bad JSON
        let bad_state = temp.join("state.json"); // With L2_DATA_DIR override, state.json is placed directly under the override dir
        std::fs::write(&bad_state, "{ this is not valid json }").unwrap();

        // Should not panic, returns default
        let sub = load_state();
        assert!(sub.systems.is_empty());

        let _ = std::env::remove_var("L2_DATA_DIR");
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn save_and_load_roundtrip_basic() {
        let temp = std::env::temp_dir().join(format!("l2-roundtrip-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp);
        std::env::set_var("L2_DATA_DIR", temp.to_str().unwrap());

        let mut sub = Substrate::default();
        let _ = sub.create("roundtrip-sys", "strict");
        let _ = save_state(&sub);

        let loaded = load_state();
        assert!(loaded.systems.values().any(|s| s.name == "roundtrip-sys"));

        let _ = std::env::remove_var("L2_DATA_DIR");
        let _ = std::fs::remove_dir_all(&temp);
    }
}
