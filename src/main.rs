//! l2 - The focused Latticra substrate CLI (host prototype)
//!
//! This version has real persistence so you can use it across multiple terminal commands.
//! State lives in ~/.l2/state.json (override with L2_DATA_DIR).

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// l2 - minimal high-assurance substrate for dynamic isolated systems.
#[derive(Parser, Debug)]
#[command(name = "l2", version, about = "Minimal high-assurance substrate (host prototype with persistence)", long_about = None)]
struct Cli {
    /// Output machine-readable JSON
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create a new isolated system
    Create {
        name: String,
        #[arg(long, default_value = "default")]
        policy: String,
    },
    /// Destroy a system (total cleanup, no residual state)
    Destroy { name: String },
    /// List systems or objects inside a system
    List { name: Option<String> },
    /// Put an object into a system
    Put {
        sys: String,
        name: String,
        #[arg(long, default_value = "data")]
        r#type: String,
        #[arg(long)]
        content: Option<String>,
    },
    /// Retrieve an object from a system
    Get { sys: String, name: String },
    /// Execute work inside a system (real Linux namespace isolation)
    Exec {
        sys: String,
        what: String,
        #[arg(long)]
        input: Option<String>,
    },
    /// Revoke a specific grant
    Revoke { sys: String, grant: String },
    /// Show substrate status
    Status { name: Option<String> },
}

// === Persistent Substrate Model ===

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

fn data_dir() -> PathBuf {
    std::env::var("L2_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").expect("HOME must be set");
            PathBuf::from(home).join(".l2")
        })
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
            .ok_or_else(|| anyhow::anyhow!("object '{}' not found in system", obj_name))
    }

    fn resolve_name(&self, name: &str) -> Result<String> {
        for (id, sys) in &self.systems {
            if sys.name == name || id == name {
                return Ok(id.clone());
            }
        }
        anyhow::bail!("system '{}' not found", name);
    }
}

// === Real host isolation for exec ===

fn exec_isolated(what: &str, input: Option<&str>, sys_name: &str) -> Result<String> {
    let mut cmd = Command::new("unshare");
    cmd.args(["--fork", "--pid", "--mount-proc", "--net", "--"])
       .arg(what);

    if let Some(i) = input {
        cmd.arg(i);
    }

    cmd.stdout(Stdio::piped())
       .stderr(Stdio::piped());

    let output = cmd.output()?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        return Ok(format!(
            "[isolated exec in '{}'] failed (code {:?})\nstdout:\n{}\nstderr:\n{}",
            sys_name, output.status.code(), stdout, stderr
        ));
    }

    Ok(format!("[isolated via unshare in '{}']\n{}", sys_name, stdout))
}

// === Output helpers ===

fn print_json<T: Serialize>(value: &T) {
    println!("{}", serde_json::to_string_pretty(value).unwrap());
}

fn success(msg: &str, json: bool) {
    if json {
        println!("{{\"ok\":true,\"msg\":\"{}\"}}", msg);
    } else {
        println!("{} {}", "✓".green(), msg);
    }
}

fn error(msg: &str, json: bool) -> ! {
    if json {
        eprintln!("{{\"ok\":false,\"err\":\"{}\"}}", msg);
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
                    let _ = save_state(&sub);
                    if cli.json {
                        print_json(&serde_json::json!({
                            "ok": true,
                            "sys": id,
                            "name": name,
                            "policy": policy
                        }));
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
            if let Err(e) = sub.destroy(&name) {
                error(&e.to_string(), cli.json);
            }
            let _ = save_state(&sub);
            success(&format!("destroyed '{}' (state persisted)", name), cli.json);
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
                            println!("  created:  {}", sys.created_at);
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
                } else {
                    if systems.is_empty() {
                        println!("No active systems.");
                        println!("Data dir: {}", data_dir().display());
                    } else {
                        println!("Active systems ({}):", systems.len());
                        for s in systems {
                            println!("  {}  {}  ({} objects)", s.id, s.name.bold(), s.objects.len());
                        }
                    }
                }
            }
        }

        Commands::Put { sys, name, r#type, content } => {
            let data = content.unwrap_or_default();
            if let Err(e) = sub.put(&sys, &name, &r#type, &data) {
                error(&e.to_string(), cli.json);
            }
            let _ = save_state(&sub);
            success(&format!("put '{}' into '{}' (type={})", name, sys, r#type), cli.json);
        }

        Commands::Get { sys, name } => {
            match sub.get(&sys, &name) {
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
            }
        }

        Commands::Exec { sys, what, input } => {
            match exec_isolated(&what, input.as_deref(), &sys) {
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

        Commands::Revoke { sys, grant } => {
            // For now just acknowledge (real revocation lives in core)
            success(&format!("revoked grant '{}' from '{}' (no-op in prototype)", grant, sys), cli.json);
        }

        Commands::Status { name } => {
            if let Some(n) = name {
                match sub.get_system(&n) {
                    Ok(sys) => {
                        if cli.json {
                            print_json(sys);
                        } else {
                            println!("System {} ({})", sys.name.bold(), sys.id);
                            println!("  policy:   {}", sys.policy);
                            println!("  objects:  {}", sys.objects.len());
                        }
                    }
                    Err(e) => error(&e.to_string(), cli.json),
                }
            } else {
                let count = sub.systems.len();
                if cli.json {
                    println!("{{\"systems\":{},\"data_dir\":\"{}\"}}", count, data_dir().display());
                } else {
                    println!("l2 host prototype (persistent)");
                    println!("  active systems: {}", count);
                    println!("  data dir:       {}", data_dir().display());
                    println!("  backend:        unshare namespaces + file persistence");
                }
            }
        }
    }

    Ok(())
}
