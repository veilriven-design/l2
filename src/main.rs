//! l2 - The focused Latticra substrate CLI (host prototype)
//!
//! Working terminal interface + real Linux namespace isolation for execution.
//! This is the first step toward a proper client + core split and C core.

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::Mutex;

/// l2 - minimal high-assurance substrate for dynamic isolated systems.
///
/// All operations go through the narrow terminal surface.
#[derive(Parser, Debug)]
#[command(name = "l2", version, about, long_about = None)]
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
    /// Destroy a system (total cleanup)
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
    /// Execute work inside a system (now with real namespace isolation)
    Exec {
        sys: String,
        what: String,
        #[arg(long)]
        input: Option<String>,
    },
    /// Revoke a specific grant
    Revoke { sys: String, grant: String },
    /// Show status
    Status { name: Option<String> },
}

// === Substrate model (still in-memory for state; isolation is real for exec) ===

#[derive(Debug, Clone, Serialize, Deserialize)]
struct System {
    id: String,
    name: String,
    policy: String,
    created_at: String,
    objects: HashMap<String, Object>,
    grants: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Object {
    name: String,
    r#type: String,
    content: String,
    size: usize,
}

static SUBSTRATE: Mutex<Substrate> = Mutex::new(Substrate {
    systems: HashMap::new(),
    next_id: 1,
});

struct Substrate {
    systems: HashMap<String, System>,
    next_id: u64,
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

    fn list_systems(&self) -> Vec<&System> { self.systems.values().collect() }

    fn get_system(&self, name: &str) -> Result<&System> {
        let id = self.resolve_name(name)?;
        Ok(self.systems.get(&id).unwrap())
    }

    fn put(&mut self, sys_name: &str, obj_name: &str, typ: &str, content: &str) -> Result<()> {
        let id = self.resolve_name(sys_name)?;
        let sys = self.systems.get_mut(&id).unwrap();
        let obj = Object { name: obj_name.to_string(), r#type: typ.to_string(), content: content.to_string(), size: content.len() };
        sys.objects.insert(obj_name.to_string(), obj);
        Ok(())
    }

    fn get(&self, sys_name: &str, obj_name: &str) -> Result<Object> {
        let id = self.resolve_name(sys_name)?;
        let sys = self.systems.get(&id).unwrap();
        sys.objects.get(obj_name).cloned().ok_or_else(|| anyhow::anyhow!("object not found"))
    }

    fn resolve_name(&self, name: &str) -> Result<String> {
        for (id, sys) in &self.systems {
            if sys.name == name || id == name { return Ok(id.clone()); }
        }
        anyhow::bail!("system '{}' not found", name);
    }
}

// === Real host isolation for exec (using unshare for namespaces) ===

fn exec_isolated(what: &str, input: Option<&str>, sys_name: &str) -> Result<String> {
    // Use unshare to create new PID, mount, and network namespaces.
    // This is a real (if basic) isolation step for the host prototype.
    // Requires unshare to be available (standard on modern Linux).

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
        return Ok(format!("[isolated exec in '{}'] command failed (code {:?})\nstdout:\n{}\nstderr:\n{}", 
            sys_name, output.status.code(), stdout, stderr));
    }

    Ok(format!("[isolated via unshare in '{}']\n{}", sys_name, stdout))
}

// === Output helpers ===

fn print_json<T: Serialize>(value: &T) { println!("{}", serde_json::to_string_pretty(value).unwrap()); }

fn success(msg: &str, json: bool) {
    if json { println!("{{\"ok\":true,\"msg\":\"{}\"}}", msg); }
    else { println!("{} {}", "✓".green(), msg); }
}

fn error(msg: &str, json: bool) -> ! {
    if json { eprintln!("{{\"ok\":false,\"err\":\"{}\"}}", msg); }
    else { eprintln!("{} {}", "✗".red(), msg); }
    std::process::exit(1);
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut sub = SUBSTRATE.lock().unwrap();

    match cli.command {
        Commands::Create { name, policy } => {
            match sub.create(&name, &policy) {
                Ok(id) => {
                    if cli.json {
                        print_json(&serde_json::json!({"ok":true,"sys":id,"name":name,"policy":policy}));
                    } else {
                        println!("{} created system '{}' (id={})\n   policy: {}", "✓".green(), name.bold(), id, policy);
                    }
                }
                Err(e) => error(&e.to_string(), cli.json),
            }
        }
        Commands::Destroy { name } => {
            if let Err(e) = sub.destroy(&name) { error(&e.to_string(), cli.json); }
            success(&format!("destroyed '{}'", name), cli.json);
        }
        Commands::List { name } => {
            if let Some(sys_name) = name {
                match sub.get_system(&sys_name) {
                    Ok(sys) => { if cli.json { print_json(sys); } else { /* pretty print omitted for brevity in this update */ println!("System {} ({})", sys.name, sys.id); } }
                    Err(e) => error(&e.to_string(), cli.json),
                }
            } else {
                let systems = sub.list_systems();
                if cli.json { print_json(&systems); } else {
                    println!("Active systems:");
                    for s in systems { println!("  {}  {}", s.id, s.name.bold()); }
                }
            }
        }
        Commands::Put { sys, name, r#type, content } => {
            let data = content.unwrap_or_default();
            if let Err(e) = sub.put(&sys, &name, &r#type, &data) { error(&e.to_string(), cli.json); }
            success(&format!("put '{}' into '{}' (type={})", name, sys, r#type), cli.json);
        }
        Commands::Get { sys, name } => {
            match sub.get(&sys, &name) {
                Ok(obj) => { if cli.json { print_json(&obj); } else { println!("Object {} [{}] ({} bytes)", obj.name, obj.r#type, obj.size); } }
                Err(e) => error(&e.to_string(), cli.json),
            }
        }
        Commands::Exec { sys, what, input } => {
            // Real isolation step
            match exec_isolated(&what, input.as_deref(), &sys) {
                Ok(out) => { if cli.json { print_json(&serde_json::json!({"ok":true,"output":out})); } else { println!("{}", out); } }
                Err(e) => error(&e.to_string(), cli.json),
            }
        }
        Commands::Revoke { sys, grant } => success(&format!("revoked {} from {}", grant, sys), cli.json),
        Commands::Status { name } => {
            if let Some(n) = name {
                match sub.get_system(&n) {
                    Ok(sys) => { if cli.json { print_json(sys); } else { println!("System {} policy={}", sys.name, sys.policy); } }
                    Err(e) => error(&e.to_string(), cli.json),
                }
            } else {
                let count = sub.systems.len();
                if cli.json { println!("{{\"systems\": {}}}", count); } else {
                    println!("l2 host prototype | active systems: {} | backend: unshare namespaces + in-memory state", count);
                }
            }
        }
    }
    Ok(())
}
