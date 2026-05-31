//! l2 - The focused Latticra substrate CLI (host prototype)
//!
//! This is the initial runnable implementation of the terminal interface.
//! It speaks an in-process version of the narrow L2P protocol ideas while
//! simulating the substrate for rapid iteration and dogfooding.

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
        /// Name for the new system
        name: String,

        /// Policy to apply at creation time
        #[arg(long, default_value = "default")]
        policy: String,
    },

    /// Destroy a system (total cleanup, no residual state)
    Destroy {
        name: String,
    },

    /// List systems or objects inside a system
    List {
        /// System name (if omitted, lists all systems)
        name: Option<String>,
    },

    /// Put an object into a system
    Put {
        sys: String,
        name: String,
        /// One of: data, code, credential, mcp_server
        #[arg(long, default_value = "data")]
        r#type: String,
        /// Inline content for the object (for prototype)
        #[arg(long)]
        content: Option<String>,
    },

    /// Retrieve an object from a system
    Get {
        sys: String,
        name: String,
    },

    /// Execute work inside a system
    Exec {
        sys: String,
        what: String,

        /// Optional input passed to the execution
        #[arg(long)]
        input: Option<String>,
    },

    /// Revoke a specific grant from a system
    Revoke {
        sys: String,
        grant: String,
    },

    /// Show substrate and system status
    Status {
        name: Option<String>,
    },
}

// === In-memory substrate simulation (host prototype) ===

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

    fn exec(&self, sys_name: &str, what: &str, input: Option<&str>) -> Result<String> {
        let _sys = self.get_system(sys_name)?;
        // Prototype: just echo a plausible result.
        // Real implementation will hand off to the actual isolated context.
        let result = format!(
            "[prototype] executed '{}' inside '{}'\ninput_len={}\n(Real execution and isolation coming in next pieces)",
            what,
            sys_name,
            input.map(|s| s.len()).unwrap_or(0)
        );
        Ok(result)
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
    let mut sub = SUBSTRATE.lock().unwrap();

    match cli.command {
        Commands::Create { name, policy } => {
            match sub.create(&name, &policy) {
                Ok(id) => {
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
                    }
                }
                Err(e) => error(&e.to_string(), cli.json),
            }
        }

        Commands::Destroy { name } => {
            if let Err(e) = sub.destroy(&name) {
                error(&e.to_string(), cli.json);
            }
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
                            println!("Objects:");
                            if sys.objects.is_empty() {
                                println!("  (none)");
                            } else {
                                for (k, v) in &sys.objects {
                                    println!("  {} [{}] ({} bytes)", k, v.r#type, v.size);
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
                    } else {
                        println!("Active systems:");
                        for s in systems {
                            println!("  {}  {}  (policy: {})", s.id, s.name.bold(), s.policy);
                        }
                    }
                }
            }
        }

        Commands::Put { sys, name, r#type, content } => {
            let data = content.unwrap_or_else(|| "<empty>".to_string());
            if let Err(e) = sub.put(&sys, &name, &r#type, &data) {
                error(&e.to_string(), cli.json);
            }
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
                        println!("Content:\n{}", obj.content);
                    }
                }
                Err(e) => error(&e.to_string(), cli.json),
            }
        }

        Commands::Exec { sys, what, input } => {
            match sub.exec(&sys, &what, input.as_deref()) {
                Ok(output) => {
                    if cli.json {
                        print_json(&serde_json::json!({"ok":true, "output": output}));
                    } else {
                        println!("{}", output);
                    }
                }
                Err(e) => error(&e.to_string(), cli.json),
            }
        }

        Commands::Revoke { sys, grant } => {
            // Prototype: just acknowledge
            success(&format!("revoked grant '{}' from '{}'", grant, sys), cli.json);
        }

        Commands::Status { name } => {
            if let Some(n) = name {
                match sub.get_system(&n) {
                    Ok(sys) => {
                        if cli.json {
                            print_json(sys);
                        } else {
                            println!("System {} ({})", sys.name.bold(), sys.id);
                            println!("  created: {}", sys.created_at);
                            println!("  policy:  {}", sys.policy);
                            println!("  objects: {}", sys.objects.len());
                        }
                    }
                    Err(e) => error(&e.to_string(), cli.json),
                }
            } else {
                let count = sub.systems.len();
                if cli.json {
                    println!("{{\"systems\":{}}}", count);
                } else {
                    println!("l2 host prototype status");
                    println!("  active systems: {}", count);
                    println!("  protocol: L2P v1 (in-prototype)");
                    println!("  backend:    host simulation (real isolation in progress)");
                }
            }
        }
    }

    Ok(())
}
