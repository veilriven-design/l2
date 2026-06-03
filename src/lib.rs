//! l2 core library (mature L2P / core split for v0.5.0).
//!
//! Provides the narrow swappable interface (L2Core trait + Host Linux backend impl)
//! that makes L2P v1 E2E exercised for create/put/exec intents etc.
//!
//! - Default: in-proc Host (Substrate under the hood) for full compat + speed.
//! - L2_USE_CORE=1: real out-of-process l2-core (host/core.rs) speaking L2P stdio
//!   using the same Host + trait.
//! - Future: seL4/Microkit PD implements the same narrow ops (caps instead of ns/Landlock).
//!
//! External `l2` CLI, policies (strict-mcp/great-harden etc), L2_DATA_DIR (incl sudo),
//! sudo escalation, sandbox, audit --test, North-Star Containment grand demos, crypto,
//! and all evidence loops are *identical* regardless of backend. This is the key
//! architectural qualifier for 0.5.0 (mature Linux Host backend via L2Core + seL4 traction).
//!
//! OpenBSD pledge(2)/unveil(2) logic is embedded in the sandbox used by Host paths
//! (Landlock for unveil-style FS, seccomp+NEVER for pledge-style syscalls). See sandbox.rs.
//!
//! See docs/PROTOCOL.md, docs/STATUS.md, docs/ROADMAP.md, and src/main.rs for usage. v0.5.9: North-Star Attack (inherent binary math net payload, improved with gen/recv) + Defense (great-harden + surfaces + enhanced audit after full sweep).

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

// audit is available via the main binary for now; will be properly re-exported after full module split.

/// Core trait for the mature L2P / core split (v0.5.0).
///
/// This is the narrow, swappable interface that defines L2P v1 E2E exercised paths.
/// - In-process default: Host (Linux backend) wrapping Substrate.
/// - Out-of-process: l2-core speaks L2P JSON over stdio (host/core.rs) and satisfies
///   equivalent ops (state narrow + exec intent ack).
/// - Future: seL4/Microkit PD implementation (see src/core/core.c, core/host.c, docs/SEL4_INTEGRATION.md)
///   with identical narrow surface (no change to external `l2` CLI iface or mental model).
///
/// External interface MUST remain the same (create/put/exec under policy + L2_DATA_DIR + audit
/// + great-harden/crypto + North-Star Containment demos + `l2 audit --test`).
///
/// Exec/sandbox primitives (unshare/Landlock/seccomp/escalate) stay host-specific for the Linux
/// prototype today; the trait provides the boundary + intent logging for audit/evidence loop.
/// This is the prerequisite for clean seL4 PD swap without user-visible changes.
pub trait L2Core {
    fn create(&mut self, name: &str, policy: &str) -> Result<String>;
    fn destroy(&mut self, name: &str) -> Result<()>;
    fn list_systems(&self) -> Vec<&System>;
    fn put(&mut self, sys_name: &str, obj_name: &str, typ: &str, content: &str) -> Result<()>;
    fn get(&self, sys_name: &str, obj_name: &str) -> Result<Object>;

    /// Exec intent: exercised E2E over L2P for stateful audit/trace (the actual heavy
    /// isolation happens in the host CLI wrapper today via escalate + apply_strict_sandbox
    /// + exec_isolated to preserve sudo/L2_DATA_DIR + full policy behavior).
    ///   Core impls (l2-core, future seL4) ack + log the intent for evidence.
    ///   Returns a note or output summary.
    fn exec(&mut self, sys_name: &str, cmd: &str, policy: &str) -> Result<String>;

    /// Revoke a specific capability grant (id) from system. Effective revocation (no ambient retention, per seL4/Capsicum/Genode).
    fn revoke(&mut self, sys_name: &str, grant: &str) -> Result<()>;
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
    fn exec(&mut self, sys_name: &str, cmd: &str, policy: &str) -> Result<String> {
        // In-proc Substrate default: record intent (real isolation is applied by caller in CLI
        // via Landlock/seccomp/unshare/escalate for full L2D/sudo compat). This keeps the
        // trait exercised E2E while preserving all existing behavior.
        let _ = self.resolve_name(sys_name)?; // validate exists (same error as before)
                                              // Policy is accepted for future per-policy core dispatch (great-harden etc).
        Ok(format!(
            "[core-exec-intent] {} under {} (isolation in host wrapper)",
            cmd, policy
        ))
    }
    fn revoke(&mut self, sys_name: &str, grant: &str) -> Result<()> {
        let id = self.resolve_name(sys_name)?;
        if let Some(sys) = self.systems.get_mut(&id) {
            sys.grants.retain(|g| g.id != grant);
        }
        Ok(())
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
    /// Grants are capabilities (inspired by seL4 caps, Capsicum fd-rights, CHERI permissions, Genode delegation).
    /// Each grant has an id and explicit rights (e.g. "fs:read-ws,write-ws", "net:none", "net:raw", "net:router", "exec").
    /// No ambient authority; all via explicit grants from core. Revocation is effective.
    /// "na" / "network-audit" gets net:raw/packet/audit for pentest (wireshark+aircrack modeled).
    /// "tomato" gets net:router/raw/config for router firmware features (firewall/QoS/monitor) that complement na on the shared masked surface.
    pub grants: Vec<Grant>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Grant {
    pub id: String,
    pub rights: Vec<String>, // e.g. ["fs:read", "fs:write-ws", "exec", "audit:log"]
    pub created_at: String,
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

/// Return the primary data dir (L2_DATA_DIR or ~/.l2 with SUDO respect).
/// Re-exported for use in audit/report discovery to keep L2_DATA_DIR
/// consistent everywhere (including sudo children and `l2 audit --test`).
pub use crate::data_dir as effective_data_dir;

/// Paths for evidence/reports so that `l2 audit --test`, harden --apply,
/// crypto --apply etc always use the same location (L2_DATA_DIR first).
/// This is a major consistency sweep item: no more mixed ~/.l2 vs L2D reports.
pub fn audit_log_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("audit.log"))
}

pub fn harden_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join("harden"))
}

pub fn crypto_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join("crypto"))
}

pub fn harden_latest_path(profile: &str) -> Result<PathBuf> {
    Ok(harden_dir()?.join(format!("{}-latest.json", profile)))
}

pub fn crypto_latest_path() -> Result<PathBuf> {
    Ok(crypto_dir()?.join("crypto-latest.json"))
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

        let now = chrono::Utc::now().to_rfc3339();

        // Initial grants as explicit capabilities (inspired by seL4 cap delegation on PD create,
        // Capsicum rights on fds, CHERI permissions, Genode recursive caps). No ambient.
        // Policies grant least-priv subset. Revoke removes specific grant id.
        let initial_grants = match policy {
            "strict-mcp" => vec![
                Grant { id: format!("g-fs-{}", id), rights: vec!["fs:read-ws".into(), "fs:write-ws".into()], created_at: now.clone() },
                Grant { id: format!("g-exec-{}", id), rights: vec!["exec".into()], created_at: now.clone() },
                Grant { id: format!("g-audit-{}", id), rights: vec!["audit:log".into()], created_at: now.clone() },
            ],
            "ransom-hardened" => vec![
                Grant { id: format!("g-fs-{}", id), rights: vec!["fs:read-ws-only".into()], created_at: now.clone() },
                Grant { id: format!("g-exec-{}", id), rights: vec!["exec".into()], created_at: now.clone() },
            ],
            "great-harden" => vec![
                Grant { id: format!("g-fs-{}", id), rights: vec!["fs:read-ws-tiny".into()], created_at: now.clone() },
                Grant { id: format!("g-exec-{}", id), rights: vec!["exec".into()], created_at: now.clone() },
                Grant { id: format!("g-net-{}", id), rights: vec!["net:none".into()], created_at: now.clone() },
            ],
            "na" | "network-audit" => vec![
                Grant { id: format!("g-fs-{}", id), rights: vec!["fs:read-ws".into(), "fs:write-ws".into()], created_at: now.clone() },
                Grant { id: format!("g-exec-{}", id), rights: vec!["exec".into()], created_at: now.clone() },
                Grant { id: format!("g-net-{}", id), rights: vec!["net:raw".into(), "net:audit".into(), "net:packet".into()], created_at: now.clone() },
                Grant { id: format!("g-audit-{}", id), rights: vec!["audit:log".into()], created_at: now.clone() },
            ],
            "tomato" => vec![
                Grant { id: format!("g-fs-{}", id), rights: vec!["fs:read-ws".into(), "fs:write-ws".into()], created_at: now.clone() },
                Grant { id: format!("g-exec-{}", id), rights: vec!["exec".into()], created_at: now.clone() },
                Grant { id: format!("g-net-{}", id), rights: vec!["net:router".into(), "net:raw".into(), "net:config".into()], created_at: now.clone() },
                Grant { id: format!("g-audit-{}", id), rights: vec!["audit:log".into()], created_at: now.clone() },
            ],
            _ => vec![],
        };

        let sys = System {
            id: id.clone(),
            name: name.to_string(),
            policy: policy.to_string(),
            created_at: now,
            objects: HashMap::new(),
            grants: initial_grants,
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

/// Host: the mature Linux backend implementation of L2Core (v0.5.0).
///
/// This provides the concrete Linux Host backend (mature for v0.5.0) that exercises the full
/// narrow L2P surface in-process by default (or via l2-core out-of-proc when L2_USE_CORE=1).
/// It owns the Substrate for state and delegates L2P ops.
///
/// Linux-specific heavy lifting (exec_isolated, apply_strict_sandbox, escalate_to_root_for_exec,
/// L2_DATA_DIR sudo preservation, audit, prepare_workspace) remains in the thin CLI + sandbox
/// for full behavioral compatibility and privilege requirements — but all paths are now behind the
/// L2Core boundary + Host so swapping the backend (to a seL4 PD speaking the same ops) changes
/// zero external behavior or CLI surface.
///
/// "L2P v1 E2E for v0.5.0": create/put/get/destroy/list + exec/revoke intents exercised
/// both in-proc (Host) and out-of-proc (l2-core). Prerequisite for seL4/Microkit.
#[derive(Default)]
pub struct Host {
    pub sub: Substrate,
}

impl Host {
    pub fn new() -> Self {
        Host { sub: load_state() }
    }

    pub fn save(&self) -> Result<()> {
        save_state(&self.sub)
    }
}

impl L2Core for Host {
    fn create(&mut self, name: &str, policy: &str) -> Result<String> {
        let id = self.sub.create(name, policy)?;
        let _ = save_state(&self.sub);
        Ok(id)
    }
    fn destroy(&mut self, name: &str) -> Result<()> {
        self.sub.destroy(name)?;
        let _ = save_state(&self.sub);
        Ok(())
    }
    fn list_systems(&self) -> Vec<&System> {
        self.sub.list_systems()
    }
    fn put(&mut self, sys_name: &str, obj_name: &str, typ: &str, content: &str) -> Result<()> {
        self.sub.put(sys_name, obj_name, typ, content)?;
        let _ = save_state(&self.sub);
        Ok(())
    }
    fn get(&self, sys_name: &str, obj_name: &str) -> Result<Object> {
        self.sub.get(sys_name, obj_name)
    }
    fn exec(&mut self, sys_name: &str, cmd: &str, policy: &str) -> Result<String> {
        // Validate + persist intent (real exec + sandbox applied by main.rs wrapper to
        // keep sudo/L2_* preservation, unshare, Landlock etc. working exactly as before).
        let _id = self.sub.resolve_name(sys_name)?;
        let _ = save_state(&self.sub);
        // The returned string is a note; actual output comes from the caller after isolation.
        Ok(format!(
            "[host-exec] {} (policy={}) — isolation + evidence via CLI wrapper + audit",
            cmd, policy
        ))
    }
    fn revoke(&mut self, sys_name: &str, grant: &str) -> Result<()> {
        let id = self.sub.resolve_name(sys_name)?;
        if let Some(sys) = self.sub.systems.get_mut(&id) {
            sys.grants.retain(|g| g.id != grant);
            // Capability revocation is effective (seL4/Capsicum/Genode style: remove from list, no forge possible).
        }
        let _ = save_state(&self.sub);
        Ok(())
    }
}

// Host (Linux backend) and L2Core are the mature split surface for v0.5.0+.
// Consumers (main.rs, host/core.rs) use l2::{Host, L2Core, ...} directly.
