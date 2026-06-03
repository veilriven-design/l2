//! na - Network Audit / Pentest tool for l2 substrate (v0.5.8+)
//!
//! "na" = network-audit. A fresh, self-contained implementation inspired by
//! Wireshark (live capture + dissection) and Aircrack-ng (injection, 802.11
//! audit primitives, deauth, basic crack sim) but designed as a *totally new*
//! minimal high-assurance tool.
//!
//! See docs/guides/HOWTO_na_and_tomato.txt for full instructions, descriptions,
//! copy-paste sequences, prerequisites, and the tomato complement pattern.
//!
//! Key properties (fits l2 North-Star Containment):
//! - Runs *inside* an l2 system under --policy na (or network-audit).
//! - Uses the masked "substrate network surface": the iface "na0" (veth peer
//!   created by l2 parent in a dedicated netns). The host only sees the other
//!   end of the veth (named veth*-h); everything is isolated and disposable.
//! - On `l2 destroy` (or oneshot end) the netns + veth surface is torn down.
//! - No ambient host network visibility or leakage by default.
//! - Still under full l2 sandbox (Landlock ws, seccomp with net-raw allowed for
//!   this policy only, no_new_privs, etc.).
//! - Explicit + auditable via l2 audit log + spirit + --test.
//!
//! Supported operations (terse, useful for tests):
//!   na list
//!   na capture <iface> [-c N] [-v]          # live pcap-style on na0 or other ifaces in the ns
//!   na scan <target> [--ports 1-1024,80,443]
//!   na inject <iface> <hex-bytes-or-simple> # raw send (for deauth sim etc)
//!   na audit <target>                       # combined basic security tests
//!   na wifi ...                             # 802.11 primitives + hwsim support if present
//!
//! The tool prefers raw AF_PACKET for capture/inject when possible (requires the
//! policy grants + root or CAP_NET_RAW inside the ws; l2 sudo exec provides it).
//!
//! Build: cargo build --release --bin na
//! Use inside l2: l2 create na-test --policy na; l2 put na-test na target/release/na ; l2 exec --policy na na-test 'na list'
//! Then destroy to dispose the surface completely.
//!
//! This is the "new thing" for network security testing from within the substrate.

use std::io::Read;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use std::process::Command;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "na",
    version,
    about = "na: substrate network-audit / pentest (Wireshark + Aircrack-ng modeled, masked + disposable)",
    long_about = "Run from inside l2 --policy na. Uses the 'na0' substrate network surface (veth in isolated netns). Fully disposed on destroy. See l2 policy na."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List network interfaces visible to this substrate surface (na0 + lo etc).
    List {},

    /// Capture packets on an interface (AF_PACKET when possible, else debug).
    /// Modeled on tshark / wireshark text mode.
    Capture {
        iface: String,
        /// Stop after N packets
        #[arg(short = 'c', long, default_value_t = 10)]
        count: usize,
        /// Verbose: show hexdump of payload
        #[arg(short = 'v', long)]
        verbose: bool,
    },

    /// Simple TCP port/service scan + banner grab (connect scan).
    /// Useful for quick security posture of a target from the masked surface.
    Scan {
        target: String,
        /// Ports e.g. 1-1024,22,80,443 or "common"
        #[arg(long, default_value = "common")]
        ports: String,
    },

    /// Raw packet injection on iface (for testing, deauth sim, etc).
    /// Provide bytes as hex string (no spaces) or use --deauth for 802.11 example.
    Inject {
        iface: String,
        /// Hex bytes e.g. deadbeef0102...
        #[arg(long)]
        hex: Option<String>,
        /// Build a simple 802.11 deauth frame (requires monitor-capable iface in ns, e.g. via hwsim)
        #[arg(long)]
        deauth: bool,
        /// Destination MAC for deauth (default ff:ff:ff:ff:ff:ff broadcast)
        #[arg(long, default_value = "ff:ff:ff:ff:ff:ff")]
        dmac: String,
        /// Source MAC
        #[arg(long, default_value = "00:11:22:33:44:55")]
        smac: String,
        /// BSSID
        #[arg(long, default_value = "00:11:22:33:44:55")]
        bssid: String,
    },

    /// Combined "audit run": list ifaces, quick scan of target, optional capture sample.
    /// Produces concise security-relevant findings.
    Audit {
        target: String,
    },

    /// WiFi / 802.11 oriented tests (aircrack-ng style).
    /// If hwsim is loaded you can create virtual radios inside the ns for fully
    /// contained wifi pentest sims (no host wifi touched).
    Wifi {
        #[command(subcommand)]
        cmd: WifiCmd,
    },
}

#[derive(Subcommand, Debug)]
enum WifiCmd {
    /// List wifi phys / interfaces (iw or /sys)
    List {},
    /// If mac80211_hwsim available, create N virtual radios for contained testing.
    /// The created monX / wlanX will appear in the substrate ns only.
    Sim {
        #[arg(long, default_value_t = 2)]
        count: usize,
    },
    /// Simple deauth injection helper (uses the inject path)
    Deauth {
        iface: String,
        #[arg(long, default_value = "00:11:22:33:44:55")]
        bssid: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::List {} => cmd_list(),
        Commands::Capture { iface, count, verbose } => cmd_capture(&iface, count, verbose),
        Commands::Scan { target, ports } => cmd_scan(&target, &ports),
        Commands::Inject { iface, hex, deauth, dmac, smac, bssid } => cmd_inject(&iface, hex.as_deref(), deauth, &dmac, &smac, &bssid),
        Commands::Audit { target } => cmd_audit(&target),
        Commands::Wifi { cmd } => cmd_wifi(cmd),
    }
}

fn cmd_list() -> Result<()> {
    println!("na list — interfaces visible on this substrate network surface");
    println!("(na0 is the masked veth surface provided by l2 --policy na)");
    println!();

    // Prefer /sys/class/net (works inside netns, no extra caps)
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for e in entries.flatten() {
            if let Ok(name) = e.file_name().into_string() {
                let flags_path = format!("/sys/class/net/{}/flags", name);
                let flags = std::fs::read_to_string(&flags_path).unwrap_or_default().trim().to_string();
                let carrier = std::fs::read_to_string(format!("/sys/class/net/{}/carrier", name)).unwrap_or_default().trim().to_string();
                let oper = if carrier == "1" { "UP" } else { "DOWN" };
                println!("  {}  (flags={} carrier={})", name, flags, oper);
            }
        }
    } else {
        // Fallback: parse /proc/net/dev
        if let Ok(content) = std::fs::read_to_string("/proc/net/dev") {
            for line in content.lines().skip(2) {
                if let Some(name) = line.split(':').next() {
                    let n = name.trim();
                    if !n.is_empty() {
                        println!("  {}", n);
                    }
                }
            }
        }
    }
    println!("\nUse: na capture na0   (the disposable substrate surface)");
    Ok(())
}

fn cmd_capture(iface: &str, count: usize, verbose: bool) -> Result<()> {
    println!("na capture {}  (count={})", iface, count);
    println!("(press Ctrl-C to stop early; AF_PACKET preferred for full frames)");
    println!();

    // Try raw AF_PACKET for real capture (needs the policy + effective root in ns)
    let sock = unsafe {
        libc::socket(libc::AF_PACKET, libc::SOCK_RAW, (libc::ETH_P_ALL as u16).to_be() as i32)
    };
    if sock < 0 {
        eprintln!("note: AF_PACKET raw socket not available ({}), falling back to debug mode", std::io::Error::last_os_error());
        return cmd_capture_debug(iface, count);
    }

    // Bind to specific iface index
    let ifindex = get_ifindex(iface)?;
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    sll.sll_ifindex = ifindex;

    let ret = unsafe {
        libc::bind(sock, &sll as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_ll>() as u32)
    };
    if ret < 0 {
        unsafe { libc::close(sock) };
        return Err(anyhow!("bind to {} failed: {}", iface, std::io::Error::last_os_error()));
    }

    let mut buf = [0u8; 65535];
    let mut captured = 0usize;
    while captured < count {
        let n = unsafe {
            libc::recvfrom(sock, buf.as_mut_ptr() as *mut _, buf.len(), 0, std::ptr::null_mut(), std::ptr::null_mut())
        };
        if n <= 0 {
            continue;
        }
        let frame = &buf[..n as usize];
        print_packet(captured + 1, frame, verbose);
        captured += 1;
    }
    unsafe { libc::close(sock) };
    Ok(())
}

fn get_ifindex(name: &str) -> Result<i32> {
    // Use ioctl SIOCGIFINDEX via a temp socket
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(anyhow!("socket for ioctl failed"));
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let cname = std::ffi::CString::new(name)?;
    // SAFETY: copy name
    for (i, b) in cname.as_bytes_with_nul().iter().enumerate().take(16) {
        ifr.ifr_name[i] = *b as libc::c_char;
    }
    let ret = unsafe { libc::ioctl(fd, libc::SIOCGIFINDEX, &mut ifr) };
    unsafe { libc::close(fd) };
    if ret < 0 {
        return Err(anyhow!("SIOCGIFINDEX for {} failed", name));
    }
    // ifru_ifindex (or ivalue) holds the index on Linux
    let idx = unsafe { ifr.ifr_ifru.ifru_ifindex };
    Ok(idx)
}

fn print_packet(num: usize, frame: &[u8], verbose: bool) {
    if frame.len() < 14 {
        println!("[{}] short frame ({} bytes)", num, frame.len());
        return;
    }
    let dst = &frame[0..6];
    let src = &frame[6..12];
    let etype = u16::from_be_bytes([frame[12], frame[13]]);
    print!("[{}] {:02x?} > {:02x?}  etype=0x{:04x}  ", num,
           src.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":"),
           dst.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":"),
           etype);

    match etype {
        0x0800 => {
            // IPv4
            if frame.len() > 34 {
                let ihl = (frame[14] & 0x0f) as usize * 4;
                let proto = frame[23];
                let src_ip = &frame[26..30];
                let dst_ip = &frame[30..34];
                print!("IPv4 {} -> {} proto={}", ip_to_str(src_ip), ip_to_str(dst_ip), proto);
                if proto == 6 && frame.len() > ihl + 14 + 20 {
                    // TCP
                    let sport = u16::from_be_bytes([frame[14+ihl], frame[14+ihl+1]]);
                    let dport = u16::from_be_bytes([frame[14+ihl+2], frame[14+ihl+3]]);
                    print!(" TCP {}>{}", sport, dport);
                } else if proto == 17 {
                    let sport = u16::from_be_bytes([frame[14+ihl], frame[14+ihl+1]]);
                    let dport = u16::from_be_bytes([frame[14+ihl+2], frame[14+ihl+3]]);
                    print!(" UDP {}>{}", sport, dport);
                }
            }
        }
        0x0806 => print!("ARP"),
        0x86dd => print!("IPv6"),
        _ => print!("other"),
    }
    println!(" len={}", frame.len());

    if verbose {
        // simple hexdump of first 64 bytes of payload
        let start = 14;
        for (i, chunk) in frame[start..].chunks(16).take(4).enumerate() {
            print!("  {:04x}: ", start + i*16);
            for b in chunk {
                print!("{:02x} ", b);
            }
            println!();
        }
    }
}

fn ip_to_str(o: &[u8]) -> String {
    format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
}

fn cmd_capture_debug(iface: &str, count: usize) -> Result<()> {
    // Fallback when no raw sock: just show what we would do + /proc/net stats
    for i in 1..=count {
        println!("[{}] (debug) would have captured frame on {} (no AF_PACKET in this env)", i, iface);
        std::thread::sleep(Duration::from_millis(50));
    }
    println!("(hint: run under l2 --policy na with sufficient caps for real capture)");
    Ok(())
}

fn cmd_scan(target: &str, ports_spec: &str) -> Result<()> {
    println!("na scan {}  ports={}", target, ports_spec);
    let ports = parse_ports(ports_spec);
    let mut open = vec![];
    for p in ports {
        let addr = format!("{}:{}", target, p);
        match addr.to_socket_addrs() {
            Ok(mut addrs) => {
                if let Some(sa) = addrs.next() {
                    match TcpStream::connect_timeout(&sa, Duration::from_millis(300)) {
                        Ok(mut s) => {
                            let _ = s.set_read_timeout(Some(Duration::from_millis(200)));
                            let mut buf = [0u8; 128];
                            let banner = match s.read(&mut buf) {
                                Ok(n) if n > 0 => String::from_utf8_lossy(&buf[..n]).trim().to_string(),
                                _ => "<no banner>".into(),
                            };
                            println!("  {}:{} OPEN  {}", target, p, banner);
                            open.push(p);
                        }
                        Err(_) => {}
                    }
                }
            }
            Err(_) => {}
        }
    }
    if open.is_empty() {
        println!("  no open ports in scanned range (or filtered by substrate surface policy)");
    } else {
        println!("  open ports: {:?}", open);
    }
    Ok(())
}

fn parse_ports(spec: &str) -> Vec<u16> {
    if spec == "common" {
        return vec![21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080];
    }
    let mut out = vec![];
    for part in spec.split(',') {
        if part.contains('-') {
            let mut it = part.split('-');
            if let (Some(a), Some(b)) = (it.next(), it.next()) {
                if let (Ok(start), Ok(end)) = (a.parse::<u16>(), b.parse::<u16>()) {
                    for p in start..=end { out.push(p); }
                }
            }
        } else if let Ok(p) = part.parse::<u16>() {
            out.push(p);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn cmd_inject(iface: &str, hex: Option<&str>, deauth: bool, dmac: &str, smac: &str, bssid: &str) -> Result<()> {
    println!("na inject on {} (substrate surface)", iface);
    let bytes = if deauth {
        // minimal 802.11 deauth frame (type 0xc0 subtype deauth)
        // Radiotap header (8 bytes) + 802.11 deauth (26 bytes typical)
        // This is a demo frame; real monitor mode + correct channel required for effect.
        build_deauth_frame(dmac, smac, bssid)
    } else if let Some(h) = hex {
        hex_to_bytes(h)?
    } else {
        return Err(anyhow!("provide --hex or --deauth"));
    };

    // Open raw packet socket and bind like capture, then sendto
    let sock = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, (libc::ETH_P_ALL as u16).to_be() as i32) };
    if sock < 0 {
        return Err(anyhow!("raw socket for inject failed (run under na policy)"));
    }
    let ifindex = get_ifindex(iface)?;
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();

    let ret = unsafe {
        libc::sendto(sock, bytes.as_ptr() as *const _, bytes.len(), 0,
                     &sll as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_ll>() as u32)
    };
    unsafe { libc::close(sock) };
    if ret < 0 {
        return Err(anyhow!("sendto failed: {}", std::io::Error::last_os_error()));
    }
    println!("  injected {} bytes on {} (surface={})", bytes.len(), iface, ifindex);
    if deauth {
        println!("  (802.11 deauth frame to {} / from {})", dmac, smac);
    }
    Ok(())
}

fn build_deauth_frame(dmac: &str, smac: &str, bssid: &str) -> Vec<u8> {
    // Very small radiotap + 802.11 deauth (management deauth code 0x0001)
    // Real frames need proper FCS, rates etc. This is for demo / contained hwsim testing.
    let mut f = vec![0u8; 8]; // radiotap minimal
    f[0] = 0x00; f[1] = 0x00; f[2] = 0x08; f[3] = 0x00; // length
    // 802.11 header
    f.push(0xc0); f.push(0x00); // type/subtype deauth
    f.push(0x00); f.push(0x00); // duration
    f.extend_from_slice(&mac_to_bytes(dmac));
    f.extend_from_slice(&mac_to_bytes(smac));
    f.extend_from_slice(&mac_to_bytes(bssid));
    f.push(0x00); f.push(0x00); // seq
    f.push(0x01); f.push(0x00); // reason code
    f
}

fn mac_to_bytes(s: &str) -> [u8;6] {
    let mut m = [0u8;6];
    let parts: Vec<&str> = s.split(':').collect();
    for (i, p) in parts.iter().take(6).enumerate() {
        if let Ok(v) = u8::from_str_radix(p, 16) { m[i] = v; }
    }
    m
}

fn hex_to_bytes(h: &str) -> Result<Vec<u8>> {
    if h.len() % 2 != 0 { return Err(anyhow!("hex must be even")); }
    let mut out = vec![];
    for i in (0..h.len()).step_by(2) {
        let b = u8::from_str_radix(&h[i..i+2], 16)?;
        out.push(b);
    }
    Ok(out)
}

fn cmd_audit(target: &str) -> Result<()> {
    println!("na audit {} (from substrate surface)", target);
    println!("====================================");
    cmd_list().ok();
    println!();
    cmd_scan(target, "common").ok();
    println!();
    println!("(for packet samples: na capture na0 -c 5 )");
    println!("(for wifi sims in a fully contained environment: na wifi sim )");
    Ok(())
}

fn cmd_wifi(cmd: WifiCmd) -> Result<()> {
    match cmd {
        WifiCmd::List {} => {
            println!("na wifi list");
            // Try iw
            let out = Command::new("iw").args(["list"]).output();
            if let Ok(o) = out {
                println!("{}", String::from_utf8_lossy(&o.stdout));
            } else {
                println!("iw not available or no wifi phys in this netns.");
                println!("To get contained wifi audit surface: modprobe mac80211_hwsim (if allowed) then na wifi sim");
            }
        }
        WifiCmd::Sim { count } => {
            println!("na wifi sim --count {}", count);
            // Create radios via hwsim
            let status = Command::new("modprobe").arg("mac80211_hwsim").args(["radios=0"]).status(); // first load
            if status.is_err() {
                eprintln!("modprobe mac80211_hwsim may require privileges or module allowed by host");
            }
            let _ = Command::new("sh").arg("-c").arg(format!("echo {} > /sys/module/mac80211_hwsim/parameters/radios 2>/dev/null || true", count)).status();
            println!("  requested {} virtual radios (hwsim). They should appear as wlanX / monX in this ns.", count);
            println!("  You can now: na capture mon0  or  na wifi deauth mon0 ...");
        }
        WifiCmd::Deauth { iface, bssid } => {
            cmd_inject(&iface, None, true, "ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", &bssid)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_ports_works() {
        assert!(parse_ports("common").len() > 5);
        assert!(parse_ports("22,80-82").contains(&81));
    }
    #[test]
    fn hex_roundtrip() {
        assert_eq!(hex_to_bytes("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }
}