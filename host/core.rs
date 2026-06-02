//! l2-core (future separate binary)
//!
//! This is the out-of-process core that speaks the narrow L2P v1 protocol
//! (defined in docs/PROTOCOL.md) over stdio. It uses the shared l2 library
//! (Substrate + L2Core trait) for state management.
//!
//! MAJOR PROGRESS (core split): Now implements a large subset of L2P ops
//! (ping, status, create, destroy, list, put, get). This demonstrates a
//! real protocol boundary. Exec/sandbox/hardening remain in the CLI for the
//! prototype phase (they drive unshare + Landlock + seccomp).
//!
//! Usage for architecture testing:
//!   L2_USE_CORE=1 l2 create ...   (main speaks L2P to this binary for state ops)
//!
//! Long-term: this (or a C/Microkit version) becomes the trusted core for seL4.

use std::io::{self, BufRead, Write};

use l2::{load_state, save_state};

fn main() {
    eprintln!(
        "l2-core: L2P v1 handler (advanced architecture prep). See docs/PROTOCOL.md + host/core.rs"
    );
    eprintln!("Uses shared Substrate for real ops. This binary + the L2Core trait are the foundation for the out-of-process + seL4 future.");

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
                // Load disk state for *this* request (core is spawned per CLI op when
                // L2_USE_CORE). Mut ops below will save. This fixes the logic error
                // where every core started empty (no persistence across l2 invocations).
                let mut sub = load_state();

                match op {
                    "ping" => {
                        serde_json::json!({"v":1, "id": id, "ok": true, "msg": "pong from l2-core (L2P v1 + shared lib)"})
                    }
                    "status" => serde_json::json!({
                        "v":1,
                        "id": id,
                        "ok": true,
                        "status": "l2-core (advanced split prep)",
                        "systems": sub.list_systems().len(),
                        "using": "shared Substrate + L2Core trait + per-req load/save"
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
                        match sub.create(name, policy) {
                            Ok(sys_id) => {
                                let _ = save_state(&sub);
                                serde_json::json!({"v":1, "id": id, "ok": true, "sys": sys_id})
                            }
                            Err(e) => {
                                serde_json::json!({"v":1, "id": id, "ok": false, "err": e.to_string()})
                            }
                        }
                    }
                    "destroy" => {
                        let sys = req.get("sys").and_then(|x| x.as_str()).unwrap_or("");
                        match sub.destroy(sys) {
                            Ok(()) => {
                                let _ = save_state(&sub);
                                serde_json::json!({"v":1, "id": id, "ok": true})
                            }
                            Err(e) => {
                                serde_json::json!({"v":1, "id": id, "ok": false, "err": e.to_string()})
                            }
                        }
                    }
                    "list" => {
                        let systems: Vec<_> =
                            sub.list_systems().iter().map(|s| s.name.clone()).collect();
                        serde_json::json!({"v":1, "id": id, "ok": true, "systems": systems})
                    }
                    "put" => {
                        let sys = req.get("sys").and_then(|x| x.as_str()).unwrap_or("");
                        let name = req.get("name").and_then(|x| x.as_str()).unwrap_or("");
                        let typ = req.get("type").and_then(|x| x.as_str()).unwrap_or("data");
                        let data = req.get("data").and_then(|x| x.as_str()).unwrap_or("");
                        // Note: v1 PROTOCOL mentions base64 for data; here we accept raw for simplicity in prototype.
                        // Real client would base64-encode large payloads.
                        match sub.put(sys, name, typ, data) {
                            Ok(()) => {
                                let _ = save_state(&sub);
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
                        match sub.get(sys, name) {
                            Ok(obj) => serde_json::json!({
                                "v":1, "id": id, "ok": true,
                                "name": obj.name,
                                "type": obj.r#type,
                                "size": obj.size,
                                "content": obj.content   // small objects ok; large would use refs
                            }),
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
