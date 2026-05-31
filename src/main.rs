//! l2 - Focused Latticra substrate (host prototype with persistence)
//!
//! State lives in ~/.l2/state.json (override with L2_DATA_DIR).
//!
//! When run under sudo, it automatically uses the original user's data directory.

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

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
    Destroy { name: String },
    List { name: Option<String> },
    Put {
        sys: String,
        name: String,
        #[arg(long, default_value = "data", help = "Type: data, code, credential, mcp_server")]
        r#type: String,
        #[arg(long, help = "Inline content")]
        content: Option<String>,
    },
    Get { sys: String, name: String },
    Exec {
        sys: String,
        what: String,
        #[arg(long)]
        input: Option<String>,
    },
    Revoke { sys: String, grant: String },
    Status { name: Option<String> },
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
        anyhow::bail!("system '{}' not found (data dir: {})", name, data_dir().display());
    }
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

fn print_json<T: Serialize>(value: &T) {
    println!("{}", serde_json::to_string_pretty(value).expect("serializing CLI JSON output"));
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut sub = load_state();

    match cli.command {
        Commands::Create { name, policy } => {
            match sub.create(&name, &policy) {
                Ok(id) => {
                    save_state(&sub)?;
                    if cli.json {
                        print_json(&serde_json::json!({"ok":true,"sys":id,"name":name,"policy":policy}));
                    } else {
                        println!("{} created system '{}' (id={})", "✓".green(), name.bold(), id);
                        println!("   policy: {}", policy);
                        println!("   state:  {}", state_path().display());
                    }
                }
                Err(e) => error(&e.to_string(), cli.json),
            }
        }
        Commands::Destroy { name } => {
            if let Err(e) = sub.destroy(&name) { error(&e.to_string(), cli.json); }
            let _ = save_state(&sub);
            success(&format!("destroyed '{}'", name), cli.json);
        }
        Commands::List { name } => {
            if let Some(sys_name) = name {
                match sub.get_system(&sys_name) {
                    Ok(sys) => {
                        if cli.json { print_json(sys); }
                        else {
                            println!("System: {} ({})", sys.name.bold(), sys.id);
                            println!("  policy:   {}", sys.policy);
                            println!("  objects:");
                            if sys.objects.is_empty() { println!("    (none)"); }
                            else {
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
                if cli.json { print_json(&systems); }
                else if systems.is_empty() {
                    println!("No active systems.");
                    println!("Data dir: {}", data_dir().display());
                } else {
                    println!("Active systems:");
                    for s in systems {
                        println!("  {}  {}  ({} objects)", s.id, s.name.bold(), s.objects.len());
                    }
                }
            }
        }
        Commands::Put { sys, name, r#type, content } => {
            let data = content.unwrap_or_default();
            if let Err(e) = sub.put(&sys, &name, &r#type, &data) { error(&e.to_string(), cli.json); }
            let _ = save_state(&sub);
            success(&format!("put '{}' into '{}'", name, sys), cli.json);
        }
        Commands::Get { sys, name } => {
            match sub.get(&sys, &name) {
                Ok(obj) => {
                    if cli.json { print_json(&obj); }
                    else {
                        println!("Object: {}", obj.name.bold());
                        println!("Type:   {}", obj.r#type);
                        println!("Size:   {} bytes", obj.size);
                        println!("---");
                        println!("{}", obj.content);
                    }
                }
                Err(e) => error(&e.to_string(), cli.json),
            }
        }
        Commands::Exec { sys, what, input } => {
            let system = sub.get_system(&sys)?;
            let workspace = match prepare_workspace(system) {
                Ok(ws) => Some(ws),
                Err(e) => {
                    eprintln!("Warning: could not prepare workspace: {}", e);
                    None
                }
            };

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
        Commands::Revoke { sys, grant } => success(&format!("revoked '{}' from '{}' (prototype)", grant, sys), cli.json),
        Commands::Status { name } => {
            if let Some(n) = name {
                match sub.get_system(&n) {
                    Ok(sys) => { if cli.json { print_json(sys); } else { println!("System {} policy={}", sys.name, sys.policy); } }
                    Err(e) => error(&e.to_string(), cli.json),
                }
            } else {
                let count = sub.systems.len();
                if cli.json { print_json(&serde_json::json!({"systems": count})); }
                else {
                    println!("l2 host prototype (persistent)");
                    println!("  active systems: {}", count);
                    println!("  data dir:       {}", data_dir().display());
                }
            }
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
}
