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
        sys: String,
        what: String,
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
            msg.push_str("\nHint: Full namespace isolation usually requires root on this system.\nTry: sudo ./target/release/l2 exec ...\n");
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
        Commands::Exec { sys, what, input } => {
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

            match exec_isolated(&what, input.as_deref(), &sys, workspace) {
                Ok(out) => {
                    if cli.json {
                        print_json(&serde_json::json!({"ok": true, "output": out}));
                    } else {
                        println!("{}", out);
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
}
