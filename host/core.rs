//! l2-core (out-of-process L2P v1 handler; mature for v0.5.0)
//!
//! Speaks the narrow L2P v1 protocol (docs/PROTOCOL.md) over stdio.
//! Uses l2::Host (Linux backend) + L2Core trait for all ops — this is the
//! exercised E2E core boundary.
//!
//! v0.5.0: L2P v1 is stable and exercised for create/put/get/destroy/list +
//! exec/revoke intents (state + audit evidence). Heavy host primitives (unshare,
//! Landlock, seccomp, escalate_to_root_for_exec preserving L2_DATA_DIR across
//! sudo) stay in the thin CLI wrapper for full behavioral compatibility.
//! External `l2` interface is identical whether using in-proc or L2_USE_CORE=1.
//!
//! This + the Host impl in the lib is the prerequisite for swapping in a seL4/
//! Microkit PD implementation (see src/core/core.c + core/host.c) with *zero*
//! change to users, policies, demos, or `l2 audit --test` North-Star evidence.
//!
//! Usage:
//!   L2_USE_CORE=1 l2 create ...   (exercises real out-of-proc L2P path)
//!   (default: in-proc Host for max compat + speed)

use std::io::{self, BufRead, Write};

use l2::{Host, L2Core}; // mature L2P v1 E2E split (v0.5.0): use Host + L2Core trait for exercised paths

fn main() {
    eprintln!(
        "l2-core: L2P v1 E2E (mature v0.5.0). Host + L2Core trait exercised. See docs/PROTOCOL.md"
    );
    eprintln!("Narrow surface for seL4 PD swap. External CLI iface + North-Star demos unchanged.");

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let handle = stdin.lock();

    for line in handle.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }

        let resp = if let Ok(req) = serde_json::from_str::<serde_json::Value>(&line) {
            let v = req.get("v").and_then(|x| x.as_i64()).unwrap_or(0);
            let op = req.get("op").and_then(|x| x.as_str()).unwrap_or("");
            let id = req.get("id").and_then(|x| x.as_str()).unwrap_or("unknown");

            if v != 1 {
                serde_json::json!({"v":1, "id": id, "ok": false, "err": "unsupported version"})
            } else {
                // Mature L2P v1 E2E (v0.5.0): use Host (the Linux backend impl of L2Core trait).
                // This exercises the full narrow protocol boundary out-of-process.
                // (Previously duplicated load + direct sub calls; now trait-driven for seL4 readiness.)
                // Exec is intentionally "intent only" here — the CLI wrapper does the real
                // escalate + sandbox + unshare so L2_DATA_DIR, sudo, and all policies work exactly.
                let mut host = Host::new();

                match op {
                    "ping" => {
                        serde_json::json!({"v":1, "id": id, "ok": true, "msg": "pong from l2-core (L2P v1 + shared lib)"})
                    }
                    "status" => serde_json::json!({
                        "v":1,
                        "id": id,
                        "ok": true,
                        "status": "l2-core (L2P v1 E2E mature for v0.5.0; Host Linux + L2Core)",
                        "systems": host.list_systems().len(),
                        "using": "l2::Host implements L2Core (state + exec intent); external CLI iface unchanged; seL4 PD ready"
                    }),
                    "create" => {
                        let name = req
                            .get("name")
                            .and_then(|x| x.as_str())
                            .unwrap_or("unnamed");
                        let policy = req
                            .get("policy")
                            .and_then(|x| x.as_str())
                            .unwrap_or("default");
                        match host.create(name, policy) {
                            Ok(sys_id) => {
                                serde_json::json!({"v":1, "id": id, "ok": true, "sys": sys_id})
                            }
                            Err(e) => {
                                serde_json::json!({"v":1, "id": id, "ok": false, "err": e.to_string()})
                            }
                        }
                    }
                    "destroy" => {
                        let sys = req.get("sys").and_then(|x| x.as_str()).unwrap_or("");
                        match host.destroy(sys) {
                            Ok(()) => {
                                serde_json::json!({"v":1, "id": id, "ok": true})
                            }
                            Err(e) => {
                                serde_json::json!({"v":1, "id": id, "ok": false, "err": e.to_string()})
                            }
                        }
                    }
                    "list" => {
                        let systems: Vec<_> =
                            host.list_systems().iter().map(|s| s.name.clone()).collect();
                        serde_json::json!({"v":1, "id": id, "ok": true, "systems": systems})
                    }
                    "put" => {
                        let sys = req.get("sys").and_then(|x| x.as_str()).unwrap_or("");
                        let name = req.get("name").and_then(|x| x.as_str()).unwrap_or("");
                        let typ = req.get("type").and_then(|x| x.as_str()).unwrap_or("data");
                        let data = req.get("data").and_then(|x| x.as_str()).unwrap_or("");
                        // Note: v1 PROTOCOL mentions base64 for data; here we accept raw for simplicity (L2P v1 exercised; large data would use refs or chunks).
                        // Real client would base64-encode large payloads.
                        match host.put(sys, name, typ, data) {
                            Ok(()) => {
                                serde_json::json!({"v":1, "id": id, "ok": true})
                            }
                            Err(e) => {
                                serde_json::json!({"v":1, "id": id, "ok": false, "err": e.to_string()})
                            }
                        }
                    }
                    "get" => {
                        let sys = req.get("sys").and_then(|x| x.as_str()).unwrap_or("");
                        let name = req.get("name").and_then(|x| x.as_str()).unwrap_or("");
                        match host.get(sys, name) {
                            Ok(obj) => serde_json::json!({
                                "v":1, "id": id, "ok": true,
                                "name": obj.name,
                                "type": obj.r#type,
                                "size": obj.size,
                                "content": obj.content
                            }),
                            Err(e) => {
                                serde_json::json!({"v":1, "id": id, "ok": false, "err": e.to_string()})
                            }
                        }
                    }
                    "revoke" => {
                        let sys = req.get("sys").and_then(|x| x.as_str()).unwrap_or("");
                        let grant = req.get("grant").and_then(|x| x.as_str()).unwrap_or("");
                        match host.revoke(sys, grant) {
                            Ok(()) => serde_json::json!({"v":1, "id": id, "ok": true}),
                            Err(e) => {
                                serde_json::json!({"v":1, "id": id, "ok": false, "err": e.to_string()})
                            }
                        }
                    }
                    "exec" => {
                        // Mature path: exec intent is exercised over L2P (validates sys + policy,
                        // records for evidence/audit). The actual unshare/Landlock/seccomp/escalate
                        // + L2_DATA_DIR preservation + sudo re-exec lives in the CLI wrapper
                        // (main.rs) so every existing contract (great-harden, ransom, sudo traces,
                        // oneshot, strict-mcp etc.) is unchanged. seL4 PDs implement the real
                        // capability exec here in future while keeping the same L2P op.
                        let sys = req.get("sys").and_then(|x| x.as_str()).unwrap_or("");
                        let cmd = req.get("cmd").and_then(|x| x.as_str()).unwrap_or("");
                        let policy = req
                            .get("policy")
                            .and_then(|x| x.as_str())
                            .unwrap_or("strict-mcp");
                        match host.exec(sys, cmd, policy) {
                            Ok(note) => {
                                serde_json::json!({"v":1, "id": id, "ok": true, "note": note})
                            }
                            Err(e) => {
                                serde_json::json!({"v":1, "id": id, "ok": false, "err": e.to_string()})
                            }
                        }
                    }
                    _ => {
                        serde_json::json!({"v":1, "id": id, "ok": false, "err": format!("unknown op: {}", op)})
                    }
                }
            }
        } else {
            serde_json::json!({"v":1, "id": "parse-error", "ok": false, "err": "bad json"})
        };

        let _ = writeln!(stdout, "{}", resp);
        let _ = stdout.flush();
    }
}
