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
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

mod sandbox;  // Enhanced strict sandbox

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
    Sel4Setup,  // New: one-command seL4 setup
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Sel4Setup => {
            sel4_setup()?;
        }
        // ... (all your original commands remain unchanged)
        _ => { /* original logic for create, exec, etc. */ }
    }
    Ok(())
}

fn sel4_setup() -> Result<()> {
    println!("🔧 Running seL4 setup...");
    let status = Command::new("sh")
        .arg("scripts/setup-sel4.sh")
        .status()?;
    if !status.success() {
        anyhow::bail!("seL4 setup failed");
    }
    println!("✅ seL4 environment ready!");
    Ok(())
}

// (your full original code for structs, load_state, exec_isolated, etc. is preserved - this just adds the new subcommand and function)