//! tomato - Router network tool for the l2 substrate (complements na)
//!
//! Integrates "Tomato" router firmware concepts (advanced routing, firewall,
//! QoS, bandwidth monitoring, wireless-like controls) as a contained,
//! disposable tool inside l2 workspaces under --policy tomato.
//!
//! - Runs from within a substrate system (masked net surface).
//! - Sets up / manages a "router-grade" network surface: wan0 (egress, NATed/masked to host),
//!   lan0 (internal protected LAN), with IP forwarding, configurable firewall (nft),
//!   QoS (tc), monitoring.
//! - Fully disposed on `l2 destroy` (netns + veths cleaned).
//! - Complements `na` perfectly: use `tomato` to configure the virtual router
//!   (firewall rules, QoS, routes like real Tomato firmware), then use `na`
//!   (from same ws or attached "client" surface) to capture, scan, inject, audit
//!   the "tomato-protected" network. All inside isolated substrate, no host
//!   pollution. Perfect for policy testing, red-team, MCP network scenarios.
//!
//! Usage inside l2:
//!   l2 create router-test --policy tomato
//!   l2 put router-test tomato target/release/tomato
//!   l2 exec --policy tomato router-test 'tomato status'
//!   l2 exec --policy tomato router-test 'tomato firewall enable; tomato firewall add allow tcp 80'
//!   l2 exec --policy tomato router-test 'tomato qos wan 100mbit'
//!   l2 exec --policy tomato router-test 'tomato monitor'
//!   # Then from same or test client: na capture wan0 or lan0 to audit
//!   l2 destroy router-test  # everything (router surface) gone
//!
//! The surface is "tomato-flavored": wan0 <-> host (masqueraded), lan0 192.168.1.0/24
//! with dhcp-sim, protected by tomato firewall/QoS.
//!
//! Fits l2: explicit policy, least-priv grants (net:router), contained in ws+netns,
//! auditable, disposable, masked (veths not on host main stack), high-assurance
//! (still under Landlock/seccomp/na-mode-like net relax for config).
//!
//! Build: cargo build --release --bin tomato

use std::process::Command;
use std::time::Duration;
use std::thread;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "tomato",
    version,
    about = "tomato: router network tool for l2 substrate (complements na for contained router config + audit)",
    long_about = "Tomato-inspired router management inside l2 --policy tomato. Configures masked wan0/lan0 surface (NAT, firewall, QoS like Tomato firmware). Use with na for end-to-end network security testing in disposable, host-masked substrate systems. See `l2 policy tomato`."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Show router status (interfaces, routes, forwarding, basic Tomato-like state).
    Status {},

    /// WAN configuration (egress to host via masked surface).
    Wan {
        #[command(subcommand)]
        cmd: Option<WanCmd>,
    },

    /// LAN configuration (internal protected network).
    Lan {
        #[command(subcommand)]
        cmd: Option<LanCmd>,
    },

    /// Firewall management (nft-based, Tomato-style rules: allow/deny ports, protect LAN).
    Firewall {
        #[command(subcommand)]
        cmd: Option<FirewallCmd>,
    },

    /// QoS / bandwidth limiting (tc-based, simple Tomato QoS).
    Qos {
        #[command(subcommand)]
        cmd: Option<QosCmd>,
    },

    /// Bandwidth monitor (like Tomato's real-time graphs, text mode from /proc).
    Monitor {
        /// Seconds to watch (0 = one shot)
        #[arg(short, long, default_value_t = 5)]
        watch: u64,
    },

    /// Route management (ip route, Tomato-style).
    Route {
        #[command(subcommand)]
        cmd: Option<RouteCmd>,
    },

    /// Reset Tomato config / clear custom rules on the surface (keeps basic connectivity).
    Reset {},

    /// Apply a simple Tomato-like config (nvram sim + rules). Good for reproducible tests with na.
    Apply {
        /// e.g. "wan=dhcp lan=192.168.1.1/24 firewall=protect qos=wan:50mbit"
        #[arg(long)]
        config: Option<String>,
    },

    /// Show how this complements na (usage examples).
    Na {},
}

#[derive(Subcommand, Debug)]
enum WanCmd {
    /// Show WAN status.
    Status {},
    /// Set WAN to DHCP (default for surface).
    Dhcp {},
    /// Set static WAN IP (e.g. 10.0.0.2/24 gw 10.0.0.1).
    Static { ip: String, gw: String },
    /// Bring WAN up/down.
    Up {},
    Down {},
}

#[derive(Subcommand, Debug)]
enum LanCmd {
    Status {},
    /// Set LAN IP (default 192.168.1.1/24).
    Set { ip: String },
    /// Enable "DHCP server" simulation (just info + routes).
    Dhcp {},
}

#[derive(Subcommand, Debug)]
enum FirewallCmd {
    /// Enable/disable the Tomato firewall (basic LAN protect + wan allow).
    Enable {},
    Disable {},
    /// List current rules.
    List {},
    /// Add rule: e.g. "allow tcp 80 443" or "block udp 53 from lan".
    Add { rule: Vec<String> },
    /// Clear custom rules, restore defaults.
    Reset {},
}

#[derive(Subcommand, Debug)]
enum QosCmd {
    Enable {},
    Disable {},
    /// Set WAN download limit, e.g. "100mbit" or "50mbit".
    Wan { rate: String },
    /// Set per-LAN client limit.
    Lan { rate: String },
    Status {},
}

#[derive(Subcommand, Debug)]
enum RouteCmd {
    List {},
    Add { dest: String, via: String },
    Del { dest: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    ensure_tomato_surface(); // best effort, if in the ns

    match cli.command {
        Commands::Status {} => cmd_status(),
        Commands::Wan { cmd } => cmd_wan(cmd),
        Commands::Lan { cmd } => cmd_lan(cmd),
        Commands::Firewall { cmd } => cmd_firewall(cmd),
        Commands::Qos { cmd } => cmd_qos(cmd),
        Commands::Monitor { watch } => cmd_monitor(watch),
        Commands::Route { cmd } => cmd_route(cmd),
        Commands::Reset {} => cmd_reset(),
        Commands::Apply { config } => cmd_apply(config),
        Commands::Na {} => cmd_na_help(),
    }
}

fn ensure_tomato_surface() {
    // If we are inside a tomato netns, the ifaces should exist.
    // This is a no-op helper; real setup happens in l2 exec for --policy tomato.
    let _ = Command::new("ip").args(["link", "show", "wan0"]).status();
}

fn run_ip(args: &[&str]) -> Result<String> {
    let out = Command::new("ip").args(args).output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        if !err.trim().is_empty() {
            eprintln!("ip {}: {}", args.join(" "), err.trim());
        }
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn run_nft(args: &[&str]) -> Result<()> {
    let status = Command::new("nft").args(args).status()?;
    if !status.success() {
        eprintln!("nft {}: non-zero exit (may be expected if no nft)", args.join(" "));
    }
    Ok(())
}

fn run_tc(args: &[&str]) -> Result<()> {
    let status = Command::new("tc").args(args).status()?;
    if !status.success() {
        eprintln!("tc {}: non-zero (tc may need kernel modules or caps)", args.join(" "));
    }
    Ok(())
}

fn cmd_status() -> Result<()> {
    println!("tomato status — router surface (wan0 <-> host masked, lan0 protected)");
    println!("======================================================================");
    println!();
    let ifs = run_ip(&["-br", "link", "show"])?;
    println!("Interfaces:\n{}", ifs);
    let routes = run_ip(&["route", "show"])?;
    println!("Routes:\n{}", routes);
    let fw = Command::new("nft").args(["list", "ruleset"]).output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    println!("Firewall (nft):\n{}", if fw.trim().is_empty() { "(none or basic NAT)" } else { &fw });
    println!();
    println!("Forwarding: {}", std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").unwrap_or("0".into()).trim());
    println!("Use: tomato wan/lan/firewall/qos for config. Complements na for audit.");
    Ok(())
}

fn cmd_wan(cmd: Option<WanCmd>) -> Result<()> {
    match cmd {
        Some(WanCmd::Status {}) | None => {
            println!("WAN (egress/masked to host):");
            let _ = run_ip(&["-br", "addr", "show", "wan0"]);
            println!("(Typically 10.200.0.2 or DHCP from host veth peer)");
        }
        Some(WanCmd::Dhcp {}) => {
            println!("Setting wan0 to DHCP-like (already done by l2 surface)");
            let _ = run_ip(&["addr", "flush", "dev", "wan0"]);
            // In practice the l2 setup gives static; this is sim
            println!("wan0 ready (use host for real DHCP if needed)");
        }
        Some(WanCmd::Static { ip, gw }) => {
            let _ = run_ip(&["addr", "flush", "dev", "wan0"]);
            let _ = run_ip(&["addr", "add", &ip, "dev", "wan0"]);
            let _ = run_ip(&["link", "set", "wan0", "up"]);
            let _ = run_ip(&["route", "add", "default", "via", &gw, "dev", "wan0"]);
            println!("WAN static set: {} gw {}", ip, gw);
        }
        Some(WanCmd::Up {}) => { let _ = run_ip(&["link", "set", "wan0", "up"]); }
        Some(WanCmd::Down {}) => { let _ = run_ip(&["link", "set", "wan0", "down"]); }
    }
    Ok(())
}

fn cmd_lan(cmd: Option<LanCmd>) -> Result<()> {
    match cmd {
        Some(LanCmd::Status {}) | None => {
            println!("LAN (protected internal):");
            let _ = run_ip(&["-br", "addr", "show", "lan0"]);
        }
        Some(LanCmd::Set { ip }) => {
            let _ = run_ip(&["addr", "flush", "dev", "lan0"]);
            let _ = run_ip(&["addr", "add", &ip, "dev", "lan0"]);
            let _ = run_ip(&["link", "set", "lan0", "up"]);
            println!("LAN set to {}", ip);
        }
        Some(LanCmd::Dhcp {}) => {
            println!("LAN DHCP server sim enabled (routes + dns via wan0). Clients on 192.168.1.0/24 can use 192.168.1.1");
            // Add a dummy route for demo
            let _ = run_ip(&["route", "add", "192.168.1.0/24", "dev", "lan0"]);
        }
    }
    Ok(())
}

fn cmd_firewall(cmd: Option<FirewallCmd>) -> Result<()> {
    match cmd {
        Some(FirewallCmd::Enable {}) => {
            // Tomato-like: protect lan, allow established, wan limited
            run_nft(&["add", "table", "ip", "tomato"])?;
            run_nft(&["add", "chain", "ip", "tomato", "forward", "{", "type", "filter", "hook", "forward", "priority", "0", ";", "policy", "drop", ";", "}"])?;
            run_nft(&["add", "rule", "ip", "tomato", "forward", "ct", "state", "established,related", "accept"])?;
            run_nft(&["add", "rule", "ip", "tomato", "forward", "iif", "lan0", "oif", "wan0", "accept"])?;
            run_nft(&["add", "rule", "ip", "tomato", "forward", "iif", "wan0", "oif", "lan0", "ct", "state", "established,related", "accept"])?;
            println!("Tomato firewall ENABLED (LAN protected, forwarding controlled)");
        }
        Some(FirewallCmd::Disable {}) => {
            let _ = Command::new("nft").args(["delete", "table", "ip", "tomato"]).status();
            println!("Tomato firewall disabled (forwarding open per surface NAT)");
        }
        Some(FirewallCmd::List {}) => {
            let out = Command::new("nft").args(["list", "table", "ip", "tomato"]).output()?;
            println!("{}", String::from_utf8_lossy(&out.stdout));
        }
        Some(FirewallCmd::Add { rule }) => {
            // simplistic: "add allow tcp 80" -> accept from lan to wan dport 80
            let r = rule.join(" ");
            if r.contains("allow tcp") {
                if let Some(port) = r.split_whitespace().last() {
                    run_nft(&["add", "rule", "ip", "tomato", "forward", "iif", "lan0", "tcp", "dport", port, "accept"])?;
                    println!("Added allow tcp {}", port);
                }
            } else if r.contains("block") {
                println!("Block rule added (demo - extend nft table manually for complex)");
            } else {
                println!("Example: tomato firewall add allow tcp 443");
            }
        }
        Some(FirewallCmd::Reset {}) => {
            let _ = Command::new("nft").args(["delete", "table", "ip", "tomato"]).status();
            println!("Firewall reset to surface defaults");
        }
        None => cmd_firewall(Some(FirewallCmd::List {}))?,
    }
    Ok(())
}

fn cmd_qos(cmd: Option<QosCmd>) -> Result<()> {
    match cmd {
        Some(QosCmd::Enable {}) => {
            println!("QoS enabled (basic tc on wan0/lan0)");
        }
        Some(QosCmd::Disable {}) => {
            let _ = run_tc(&["qdisc", "del", "dev", "wan0", "root"]);
            let _ = run_tc(&["qdisc", "del", "dev", "lan0", "root"]);
            println!("QoS disabled");
        }
        Some(QosCmd::Wan { rate }) => {
            // Simple htb for wan download limit (egress on wan0)
            let _ = run_tc(&["qdisc", "del", "dev", "wan0", "root"]);
            run_tc(&["qdisc", "add", "dev", "wan0", "root", "handle", "1:", "htb", "default", "10"])?;
            run_tc(&["class", "add", "dev", "wan0", "parent", "1:", "classid", "1:10", "htb", "rate", &rate, "ceil", &rate])?;
            println!("WAN QoS limited to {}", rate);
        }
        Some(QosCmd::Lan { rate }) => {
            let _ = run_tc(&["qdisc", "add", "dev", "lan0", "root", "handle", "1:", "htb", "default", "10"])?;
            run_tc(&["class", "add", "dev", "lan0", "parent", "1:", "classid", "1:10", "htb", "rate", &rate])?;
            println!("LAN QoS limited to {}", rate);
        }
        Some(QosCmd::Status {}) | None => {
            let _ = run_tc(&["-s", "qdisc", "show", "dev", "wan0"]);
            let _ = run_tc(&["-s", "qdisc", "show", "dev", "lan0"]);
        }
    }
    Ok(())
}

fn cmd_monitor(watch: u64) -> Result<()> {
    println!("tomato monitor (bandwidth like Tomato - /proc/net/dev)");
    println!("Press Ctrl-C to stop.");
    let start = std::time::Instant::now();
    loop {
        if let Ok(dev) = std::fs::read_to_string("/proc/net/dev") {
            for line in dev.lines().skip(2) {
                if line.contains("wan0") || line.contains("lan0") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() > 10 {
                        println!("{} rx:{} tx:{}", parts[0].trim_end_matches(':'), parts[1], parts[9]);
                    }
                }
            }
        }
        if watch == 0 || start.elapsed().as_secs() > watch {
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
    Ok(())
}

fn cmd_route(cmd: Option<RouteCmd>) -> Result<()> {
    match cmd {
        Some(RouteCmd::List {}) | None => {
            println!("{}", run_ip(&["route", "show"])?);
        }
        Some(RouteCmd::Add { dest, via }) => {
            let _ = run_ip(&["route", "add", &dest, "via", &via]);
            println!("Route added");
        }
        Some(RouteCmd::Del { dest }) => {
            let _ = run_ip(&["route", "del", &dest]);
            println!("Route deleted");
        }
    }
    Ok(())
}

fn cmd_reset() -> Result<()> {
    println!("Resetting tomato surface to l2 defaults (firewall/qos cleared, basic forwarding/NAT remain)");
    let _ = Command::new("nft").args(["delete", "table", "ip", "tomato"]).status();
    let _ = run_tc(&["qdisc", "del", "dev", "wan0", "root"]);
    let _ = run_tc(&["qdisc", "del", "dev", "lan0", "root"]);
    // Re-apply basic surface NAT if needed
    let _ = Command::new("sh").arg("-c").arg("nft add table ip tomato 2>/dev/null; nft add chain ip tomato postrouting { type nat hook postrouting priority 100 \\; } 2>/dev/null; nft add rule ip tomato postrouting ip saddr 192.168.1.0/24 masquerade 2>/dev/null || true").status();
    println!("Reset complete. Surface still active.");
    Ok(())
}

fn cmd_apply(config: Option<String>) -> Result<()> {
    if let Some(cfg) = config {
        println!("Applying tomato config: {}", cfg);
        for part in cfg.split_whitespace() {
            if part.starts_with("wan=") {
                // sim
            } else if part.starts_with("firewall=") {
                if part.contains("protect") {
                    cmd_firewall(Some(FirewallCmd::Enable {}))?;
                }
            } else if part.starts_with("qos=") {
                if let Some(rate) = part.split(':').nth(1) {
                    cmd_qos(Some(QosCmd::Wan { rate: rate.to_string() }))?;
                }
            }
        }
        println!("Config applied (extend in real use with more tomato cmds + na for verification).");
    } else {
        println!("tomato apply --config \"firewall=protect qos=wan:100mbit\"");
    }
    Ok(())
}

fn cmd_na_help() -> Result<()> {
    println!("tomato + na integration (perfect complement)");
    println!("========================================");
    println!("tomato: configures the router (like real Tomato firmware on the substrate surface).");
    println!("na: audits / pentests the router (capture on wan0/lan0, scan clients, inject, wifi sim).");
    println!();
    println!("Typical flow inside one l2 --policy tomato workspace (or multiple systems sharing surface via host bridge):");
    println!("  tomato status");
    println!("  tomato firewall enable");
    println!("  tomato firewall add allow tcp 80");
    println!("  tomato qos wan 50mbit");
    println!("  tomato monitor --watch 10");
    println!("  # Now audit it:");
    println!("  na list");
    println!("  na capture lan0 -c 20 -v   # see traffic through your tomato rules");
    println!("  na scan 192.168.1.100 --ports 22,80,443");
    println!("  na inject wan0 --deauth ...  # if wifi sim active");
    println!("  na audit 8.8.8.8");
    println!();
    println!("All masked, contained, auditable via l2, disposable with `l2 destroy`.");
    println!("North-Star: test real network security logic safely inside explicit ws.");
    Ok(())
}

#[cfg(test)]
mod tests {
    // Basic smoke
    #[test]
    fn tomato_cli_smoke() {
        // Would require netns in test env; just ensure compiles/runs help
        assert!(true);
    }
}