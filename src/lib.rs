//! l2 core library (architecture prep for split).
//!
//! This module contains the core state management (Substrate) and related
//! helpers. The goal is a clear boundary so the thin CLI (`src/main.rs`)
//! and the out-of-process `l2-core` (host/core.rs) can share or call into
//! the same logic (today in-process simulation, tomorrow over L2P).
//!
//! See docs/PROTOCOL.md and STATUS.md for the split plan.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

// audit is available via the main binary for now; will be properly re-exported after full module split.

/// Simple core trait for architecture prep (clear boundary for the split).
/// The CLI and l2-core can both use implementations of this.
/// This is the key interface for the L2P protocol implementation (see host/core.rs
/// and docs/PROTOCOL.md). Extended as part of major core split progress.
pub trait L2Core {
    fn create(&mut self, name: &str, policy: &str) -> Result<String>;
    fn destroy(&mut self, name: &str) -> Result<()>;
    fn list_systems(&self) -> Vec<&System>;
    fn put(&mut self, sys_name: &str, obj_name: &str, typ: &str, content: &str) -> Result<()>;
    fn get(&self, sys_name: &str, obj_name: &str) -> Result<Object>;
    // exec and revoke remain primarily in the CLI wrapper for the prototype
    // (they involve heavy host primitives + sandboxing today).
}

impl L2Core for Substrate {
    fn create(&mut self, name: &str, policy: &str) -> Result<String> {
        Substrate::create(self, name, policy)
    }
    fn destroy(&mut self, name: &str) -> Result<()> {
        Substrate::destroy(self, name)
    }
    fn list_systems(&self) -> Vec<&System> {
        Substrate::list_systems(self)
    }
    fn put(&mut self, sys_name: &str, obj_name: &str, typ: &str, content: &str) -> Result<()> {
        Substrate::put(self, sys_name, obj_name, typ, content)
    }
    fn get(&self, sys_name: &str, obj_name: &str) -> Result<Object> {
        Substrate::get(self, sys_name, obj_name)
    }
}

/// Best-effort cleanup helper (moved to lib for shared use in architecture prep).
/// Logs a warning on failure.
pub fn warn_on_cleanup_err<E: std::fmt::Display>(result: Result<(), E>, context: &str) {
    if let Err(e) = result {
        eprintln!("warning: {}: {}", context, e);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct System {
    pub id: String,
    pub name: String,
    pub policy: String,
    pub created_at: String,
    pub objects: HashMap<String, Object>,
    pub grants: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Object {
    pub name: String,
    pub r#type: String,
    pub content: String,
    pub size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Substrate {
    pub systems: HashMap<String, System>,
    pub next_id: u64,
}

pub fn data_dir() -> Result<PathBuf> {
    // Highest priority: explicit override
    if let Ok(dir) = std::env::var("L2_DATA_DIR") {
        return Ok(PathBuf::from(dir));
    }

    // If running under sudo, try to use the original user's home directory
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if let Some(home) = get_home_for_user(&sudo_user) {
            return Ok(PathBuf::from(home).join(".l2"));
        }
    }

    // Normal case
    let home = std::env::var("HOME").map_err(|_| {
        anyhow::anyhow!(
            "HOME environment variable is not set (required for default data directory)"
        )
    })?;
    Ok(PathBuf::from(home).join(".l2"))
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

pub fn state_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("state.json"))
}

pub fn load_state() -> Substrate {
    let path = match state_path() {
        Ok(p) => p,
        Err(_) => return Substrate::default(),
    };
    if !path.exists() {
        return Substrate::default();
    }
    match fs::read_to_string(&path) {
        Ok(contents) => match serde_json::from_str(&contents) {
            Ok(sub) => sub,
            Err(e) => {
                eprintln!(
                    "warning: corrupt state file at {} ({}); starting fresh",
                    path.display(),
                    e
                );
                Substrate::default()
            }
        },
        Err(_) => Substrate::default(),
    }
}

pub fn save_state(sub: &Substrate) -> Result<()> {
    let dir = data_dir()?;
    fs::create_dir_all(&dir)?;
    let path = state_path()?;
    let json = serde_json::to_string_pretty(sub)?;
    fs::write(path, json)?;
    Ok(())
}

pub fn object_relative_path(name: &str) -> Result<PathBuf> {
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

pub fn object_workspace_path(workspace: &Path, name: &str) -> Result<PathBuf> {
    Ok(workspace.join(object_relative_path(name)?))
}

pub fn workspace_dir(sys: &System) -> Result<PathBuf> {
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

pub fn prepare_workspace(sys: &System) -> Result<PathBuf> {
    let ws = workspace_dir(sys)?;
    warn_on_cleanup_err(
        fs::remove_dir_all(&ws),
        "failed to remove previous workspace dir",
    );
    fs::create_dir_all(&ws)?;

    for (name, obj) in &sys.objects {
        let path = object_workspace_path(&ws, name)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, &obj.content)?;

        if has_shebang(&obj.content) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = fs::metadata(&path) {
                    let mut perms = meta.permissions();
                    perms.set_mode(0o755);
                    warn_on_cleanup_err(
                        fs::set_permissions(&path, perms),
                        "failed to set executable permission on shebang object",
                    );
                }
            }
        }
    }
    Ok(ws)
}

impl Substrate {
    pub fn create(&mut self, name: &str, policy: &str) -> Result<String> {
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

    pub fn destroy(&mut self, name: &str) -> Result<()> {
        let id = self.resolve_name(name)?;
        self.systems.remove(&id);
        Ok(())
    }

    pub fn list_systems(&self) -> Vec<&System> {
        self.systems.values().collect()
    }

    pub fn get_system(&self, name: &str) -> Result<&System> {
        let id = self.resolve_name(name)?;
        Ok(self
            .systems
            .get(&id)
            .expect("system must exist after successful resolve_name"))
    }

    pub fn put(&mut self, sys_name: &str, obj_name: &str, typ: &str, content: &str) -> Result<()> {
        object_relative_path(obj_name)?;
        let id = self.resolve_name(sys_name)?;
        let sys = self
            .systems
            .get_mut(&id)
            .expect("system must exist after successful resolve_name");
        let obj = Object {
            name: obj_name.to_string(),
            r#type: typ.to_string(),
            content: content.to_string(),
            size: content.len(),
        };
        sys.objects.insert(obj_name.to_string(), obj);
        Ok(())
    }

    pub fn get(&self, sys_name: &str, obj_name: &str) -> Result<Object> {
        let id = self.resolve_name(sys_name)?;
        let sys = self
            .systems
            .get(&id)
            .expect("system must exist after successful resolve_name");
        sys.objects
            .get(obj_name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("object '{}' not found", obj_name))
    }

    pub fn resolve_name(&self, name: &str) -> Result<String> {
        for (id, sys) in &self.systems {
            if sys.name == name || id == name {
                return Ok(id.clone());
            }
        }
        anyhow::bail!(
            "system '{}' not found (data dir: {})",
            name,
            data_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<unknown>".into())
        );
    }
}

// Helper from original (kept here for prepare_workspace)
fn has_shebang(content: &str) -> bool {
    content
        .lines()
        .next()
        .is_some_and(|first| first.starts_with("#!"))
}
