//! l2-core (future separate binary)
//!
//! This will become the out-of-process core that speaks L2P v1 over stdio
//! or a unix socket, implementing the narrow protocol defined in docs/PROTOCOL.md.
//!
//! Architecture prep phase: basic L2P handler for a few ops (ping, status).
//! Real isolation, persistence, and C backend come later. The main `l2` binary
//! still does everything in-process for now.

/* Planned structure (from docs/PROTOCOL.md):
 * - Read JSON lines from stdin (L2P requests)
 * - Each request: {"v":1, "op":"...", "id":"req-1", ...}
 * - Dispatch to core implementation
 * - Write responses: {"v":1, "id":"req-1", "ok":true, ...}
 * - Manage actual isolated contexts (namespaces today, seL4 later)
 *
 * Current status (prep): This binary can be run standalone and will
 * respond to basic L2P messages over stdio. Useful for testing the
 * protocol boundary before full split.
 */

use std::io::{self, BufRead, Write};

fn main() {
    eprintln!("l2-core: basic L2P handler (architecture prep). See docs/PROTOCOL.md");
    eprintln!("Now uses the shared core library (Substrate) for real (in-memory) ops.");
    eprintln!("This demonstrates the boundary before full out-of-process + C core.");

    let mut core: Box<dyn l2::L2Core> = Box::new(l2::Substrate::default());

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
                match op {
                    "ping" => {
                        serde_json::json!({"v":1, "id": id, "ok": true, "msg": "pong from core lib"})
                    }
                    "status" => serde_json::json!({
                        "v":1,
                        "id": id,
                        "ok": true,
                        "status": "l2-core (using shared Substrate)",
                        "systems": core.list_systems().len()
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
                        match core.create(name, policy) {
                            Ok(sys_id) => {
                                serde_json::json!({"v":1, "id": id, "ok": true, "sys": sys_id})
                            }
                            Err(e) => {
                                serde_json::json!({"v":1, "id": id, "ok": false, "err": e.to_string()})
                            }
                        }
                    }
                    "list" => {
                        let systems: Vec<_> =
                            core.list_systems().iter().map(|s| s.name.clone()).collect();
                        serde_json::json!({"v":1, "id": id, "ok": true, "systems": systems})
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
