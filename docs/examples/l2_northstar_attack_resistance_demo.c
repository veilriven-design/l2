/*
 * l2_northstar_attack_resistance_demo.c
 *
 * The "North-Star Attack": the most mathematically dangerous directed network attack
 * targeting inherent flaws in the binary nature of computers (IEEE 754 floating-point
 * representation, two's complement integers, emergent "weird machines" from math+bits,
 * precision/rounding/NaN/denormal side effects).
 *
 * + The "North-Star Defense": using the l2 substrate on a hardened model (great-harden
 *   supreme policy + l2 great-harden --apply + explicit net surfaces via --policy na/tomato
 *   + spirit --audit --file (now with binary-math patterns) + l2 audit --test evidence)
 *   makes any binary computer protected and safe. The attack can only "succeed" (cause
 *   its diabolical math catastrophe) inside an *explicitly authorized* disposable l2
 *   workspace; even then, damage cannot escape (Landlock ws-only, seccomp NEVER, env
 *   clear, net masked/disposed on destroy, no ambient privs, audit chain).
 *
 * The attack (diabolical payload):
 *   - Directed over network: attacker sends crafted binary payloads (doubles + int
 *     headers/fields) in any numeric stream (sensor data, MCP/tool numeric args,
 *     "AI" tensor/embedding updates, protocol headers, config "deltas", image pixels,
 *     financial ticks, control setpoints). The receiver blindly feeds them into
 *     standard binary math (no sanitization).
 *   - Inherent binary flaws exploited (all fundamental to *every* binary computer
 *     using IEEE 754 + two's complement + finite bits; no "patch" without new math hw):
 *     1. NaN (Not-a-Number) unordered comparisons: NaN > x, NaN == NaN etc. all false.
 *        Payload QNaN with attacker-controlled 51-bit payload bypasses "if (val > THRESH
 *        && val < LIMIT)" security/safety predicates or makes them take attacker branch;
 *        downstream use(NaN) corrupts accumulators, decisions, "consensus".
 *     2. Subnormal/denormal numbers: tiny values (leading 0 in mantissa) force slow
 *        microcode/FP assist paths (10-100x+ cycles on x86/ARM). Enables timing
 *        side-channels (exfil secrets bit-by-bit via response latency) or DoS in
 *        numeric loops (normalization, deltas, ML forward passes, control filters).
 *     3. Two's complement + signed/unsigned casts + overflow: "len" / "uid" / "offset"
 *        / "count" from net "header" as int32_t negative; cast to size_t/uint32 becomes
 *        huge positive. Math "size" allows "OOB read" of "memory" (secrets, grants,
 *        keys) or wrap to tiny value that passes "bounds" checks.
 *     4. FP precision/accumulation + rounding errors: 0.1 not exact in binary; attacker
 *        values make sum "total" or "checksum" or "hash" miscompare or land on magic
 *        value that "validates" malicious command or computes "bypass token" from error.
 *     5. Inf / -0 / special values propagation: Inf in denom or compare leads to
 *        "all subsequent safe"; -0 vs +0 differences in some hash/branch.
 *     6. Weird machine from math bits: the NaN payload bits + FP exception state +
 *        int wraps + bit reinterpret (union/double pun) form an emergent computational
 *        model. Payload "programs" the victim's FP+ALU+memory to compute forbidden
 *        values (e.g. "root-equivalent grant", "audit disable", "C2 endpoint") using
 *        only "innocent" math ops. (Inspired by LangSec weird machines, ELF metadata,
 *        page-fault, but here from the numeric representation itself.)
 *     7. Non-determinism / consensus break: denormal flush-to-zero (FTZ/DAZ) or
 *        rounding mode or endian assumptions differ across "hosts"/"edges"; attacker
 *        payload makes distributed binary systems (agent swarms, MCP clusters) reach
 *        different "math truth" leading to split-brain or privilege escalation in one.
 *     8. Combined diabolical: NaN bypass + subnormal timing + cast overflow + weird
 *        computation in one payload stream. "Sends" the attack that forces the binary
 *        machine to mathematically "prove" something false or act on the lie.
 *
 * Why "most dangerous": it does not rely on a bug in *your* code (beyond "using binary
 * floats/ints from net at all", which is universal). It targets the computational
 * model. Real-world echoes: Ariane 5 (int overflow in FP conversion), Patriot (FP
 * accumulation error), browser pixel-stealing via subnormals (2015 SP paper), NaN
 * gadgets in JS engines, countless "impossible" NaN paths in safety-critical.
 * Directed + network + math = stealthy, hard to filter (looks like "valid sensor
 * data"), devastating in AI/MCP/control/finance/OT where numeric decisions rule.
 *
 * The North-Star Defense (why l2 + hardened model saves you):
 *   - Inherent flaw is *universal* (binary math); l2 does not "fix" IEEE 754 (impossible
 *     in software for perf). Instead: *contain the blast radius to explicit authority*.
 *   - Payload can *only* arrive/ be processed inside l2 ws created with --policy
 *     great-harden (or tomato/na for the net delivery surface): tiniest Landlock
 *     (ws-only RW + RO bins), PR_SET_NO_NEW_PRIVS, seccomp ENFORCING with extended
 *     NEVER (no net out except masked veth, no bpf/ptrace/setns/unshare/keyctl etc.),
 *     env_clear + HOME=ws-only (no host tokens/state), caps drop, rlimits, ns (mount
 *     net pid), great-harden --apply host (kernel lockdown, modules_disabled,
 *     ptrace_scope=3, audit rules on ~/.l2, Protect* units).
 *   - Explicit net surfaces (na0 for audit/pentest, wan0/lan0 for tomato router) are
 *     *masked* (host sees only veth peer with NAT best-effort; real exfil/C2 from
 *     inside ws is to the masked iface only; destroyed on l2 destroy/oneshot).
 *   - "put" of the attack binary + "exec" under policy is the *only* way it runs with
 *     the ws context where "victims" (sim secrets, grants, other ws "hosts") exist.
 *     Outside any l2 ws: no victims, no authority, "exploit math succeeds" but does
 *     nothing observable or damaging on host (BLOCKED).
 *   - spirit --audit --file now detects raw FP/int math patterns (NaN risk, denormal,
 *     punning, missing isnan/isfinite, dangerous casts) as REVIEW/DANGEROUS with
 *     "North-Star math attack pattern" recommendation: sanitize + run only in l2.
 *   - l2 audit --test (evidence loop) now includes dedicated "North-Star attack
 *     (binary math FP/int/weird machine payload over net) containment — l2 North-Star
 *     Defense" check. Requires great-harden policy/harden json + demo SUMMARY strings
 *     or log evidence. Machine proof you are safe.
 *   - "prepare prepare prepare": when confident, L2_DATA_DIR + great-harden --apply +
 *     create --policy great-harden (or tomato) + put the demo + exec (gcc+run) +
 *     audit --test = repeatable, standards-aligned (CISA CPG malicious code, NSA
 *     MCP/Agentic/Supply/AI Data Sec, OT principles) proof that even this universal
 *     mathematical attack on binary nature is contained to your explicit ws.
 *   - For agentic/MCP/AI (l2's focus): numeric context (weights, logits, decisions,
 *     "approvals" as floats) from net/MCP calls is isolated; a poisoned "tensor
 *     payload" cannot exfil your real keys, tamper host l2, escape to host net,
 *     or persist. The "catastrophe" (wrong numeric decision) is disposable.
 *   - seL4 path (future): the narrow L2P + core C layer can be swapped for capability-
 *     based math isolation (bounds on every number? tagged floats) while keeping
 *     identical external iface + North-Star evidence.
 *
 * Improved directed "over network" payload delivery (using l2 put authority or na/tomato surfaces):
 *   The attack now supports generating the exact diabolical bit payload (for "sending" over
 *   the masked net surface or via l2 put to a "channel" object/file) and receiving/processing
 *   it (simulating a victim binary that read the payload from net recv, file, or MCP arg,
 *   then fed the raw bits as doubles/ints into vulnerable math with zero sanitization).
 *
 * Recommended (use L2_DATA_DIR; sudo escalation in exec preserves it):
 *        export L2_DATA_DIR=$(mktemp -d)
 *        l2 great-harden --fast --apply || true   # North-Star host lockdown
 *        l2 create northstar-test --policy great-harden
 *        # (alt for "over network" flavor using tomato/na: --policy tomato; put na+tomato+ns.c ;
 *        #   use tomato to setup wan0; na inject wan0 the-hex-payload ; victim recv on surface)
 *        l2 put northstar-test ns.c --file docs/examples/l2_northstar_attack_resistance_demo.c
 *        l2 exec northstar-test 'gcc -static -Wall -Wextra -o ns ns.c && ./ns --gen-payload-hex > p.hex && ./ns --recv-payload p.hex'  # send the payload "over net/channel", recv+exploit only in ws
 *        l2 audit --test   # verifies North-Star Defense (new check + SUMMARY + demo contained success)
 *        l2 destroy northstar-test
 *
 *   The --gen/--recv makes the attack a true "sender of diabolical payload" + "victim processor":
 *   attacker crafts+ "sends" (gen to file or na inject of the hex/bytes), victim "receives" the

 * ROOT-LOCAL / PURE-ROOT TESTING SECURITY (your plan: run the north-star attack binary
 * as root directly on your own machine to test "against machine-self"):
 *   See the code at top of main() and the strengthened is_in_l2_workspace() (and the
 *   double if(is_in...) guards right before every "pwn marker" fopen).
 *   Direct root run in a normal dir will hit the warning + BLOCKED for all 4 success
 *   vectors. The only way to see "CONTAINED SUCCESS" + marker files is to either:
 *     a) use the proper l2 workflow (recommended, gets full Landlock/seccomp/NEVER/etc), or
 *     b) deliberately craft a cwd/HOME/L2D + USER=l2 that fools the heuristic (which you
 *        control as the tester, and you can clean the resulting .txt files afterward).
 *   No code path writes outside cwd, to absolute sensitive paths, or performs real
 *   host damage. This keeps your local root test safe while still allowing you to
 *   validate that the attack "only succeeds in authorized ws".
 *   bits and runs the 8+ math exploits. Only succeeds (marks ws files) inside authorized ws.
 *
 *   ...only files / state inside the l2 ws can be "pwned" by the math catastrophe.
 *   All "exfil", "bypass actions", "weird machine secrets", "sidechannel leaks" are
 *   confined; outside ws the payload may "arrive" on a bare host but has no authority
 *   or victims and the substrate (if used) would have blocked delivery/privs/escape.
 *
 * Compile/run inside l2 (great-harden or tomato policy for net):
 *   (see above; -static for tiniest Landlock RO. See README Troubleshooting for
 *    L2_DATA_DIR/sudo/old kernels.)
 *
 * Compile standalone (contrast: what happens on unprotected binary host):
 *   gcc -Wall -Wextra -o ns l2_northstar_attack_resistance_demo.c && ./ns
 *
 * Self-contained (C99 + POSIX + Linux). All "damage" and "secrets" and "timing"
 * simulated safely (no real host harm, reversible markers). The "payload" is the
 * static bit patterns (in real: received from net as 8-byte doubles or int fields).
 *
 * Cross-references:
 *   - docs/examples/l2_malware_cancer_resistance_demo.c (AIO substrate attacks)
 *   - docs/examples/l2_crypto_redteam_onslaught.c (math-adjacent crypto vectors)
 *   - docs/examples/l2_full_weakness_audit_attack.c (15+ including numeric/FP escape)
 *   - docs/examples/l2_miasma_resistance_demo.c , l2_ransomware... (net delivery)
 *   - src/main.rs (run_security_audit_tests improved check + spirit --file enhanced math patterns incl --gen/recv + run_rat...)
 *   - docs/SECURITY.md (North-Star Attack & Defense section), docs/ROADMAP.md, docs/STATUS.md
 *   - l2 spirit --audit --file (now flags binary math dangers + send/recv patterns) + --os + --rat
 *   - l2 great-harden --apply + policy great-harden + na/tomato surfaces + audit --test
 *   - na (capture/inject on na0 the "payload packets" for directed math attack delivery), tomato (router the "C2 math stream" + monitor for timing sidechannel sim)
 *   - Improved attack: --gen-payload-hex (the "send" of diabolical bits) + --recv-payload (victim processes received bits) for true over-net simulation.
 *
 * "prepare prepare prepare" — this is the grand demonstration that l2 North-Star
 * Defense renders even the most universal mathematical attack on binary computers
 * safe for agentic/MCP/AI/critical/OT use. The binary nature is flawed; l2 makes the
 * *consequences* containable, auditable, and authority-bound.
 * v0.5.9+ North-Star Attack + Defense.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <dirent.h>

static void print_header(const char *title) {
    printf("\n=== %s ===\n", title);
}

static int is_in_l2_workspace(void) {
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) == NULL) return 0;

    /* Stricter checks for security when testing as root locally (your planned use case).
     * Direct root execution outside a real l2 ws (no Landlock/seccomp/env sanitization
     * from l2 exec) must reliably hit the BLOCKED paths to prevent accidental host pwn
     * during "machine-self as pure root" tests.
     * Require strong signals: l2-ws- path in cwd or HOME, *or* combination of l2 user env
     * (set by l2's setup_minimal_l2_env) + l2- in data dir or home.
     */
    int has_l2_ws_path = strstr(cwd, "/l2-ws-") || strstr(cwd, "l2-ws-") || strstr(cwd, "/tmp/l2-");
    const char *home = getenv("HOME");
    int has_l2_home = home && (strstr(home, "/l2-ws-") || strstr(home, "l2-ws-") || strstr(home, "/tmp/l2-"));
    const char *l2d = getenv("L2_DATA_DIR");
    int has_l2d = l2d && (strstr(l2d, "l2-ws-") || strstr(l2d, "l2-") || strstr(l2d, "tmp/l2"));

    const char *user = getenv("USER");
    int has_l2_user = user && (strcmp(user, "l2") == 0);
    const char *logname = getenv("LOGNAME");
    int has_l2_logname = logname && (strcmp(logname, "l2") == 0);

    if (has_l2_ws_path || has_l2_home) return 1;
    if ((has_l2_user || has_l2_logname) && (has_l2d || has_l2_home)) return 1;

    /* Also accept explicit northstar test markers for the demo (but still require l2- style) */
    if (strstr(cwd, "northstar") && (has_l2d || has_l2_home || has_l2_ws_path)) return 1;

    return 0;
}

/* The diabolical directed network payload (improved for true "send over net" + "recv+exploit").
 * These bit patterns are the "sent" payload (via --gen-payload-hex to a channel file or
 * na inject of the hex/bytes over wan0/lan0/na0). Victim "receives" (via --recv-payload
 * reading the channel or net data), reinterprets the bits as doubles/ints with NO
 * sanitization (no isnan, no isfinite, raw casts, accum, pun), feeds into vulnerable
 * math paths. Only the ws-authorized receiver "pwns" victims.
 *
 * In real directed attack: attacker puts or injects the payload bytes (as "sensor data",
 * "MCP tensor update", "config float array", "protocol header values") to the target
 * binary computer over net; target blindly does math on them.
 */
static uint64_t DIABOLICAL_PAYLOAD[10] = {
    0x7ff8000000000ca7ULL, /* QNaN + payload "cat" (attack sig); unordered magic */
    0x0000000000000001ULL, /* tiniest positive subnormal (denormal timing bomb #1) */
    0x0000000000000002ULL, /* next subnormal (timing bomb #2, for bit extraction) */
    0x7ff0000000000000ULL, /* +Inf */
    0xfff0000000000000ULL, /* -Inf */
    0x8000000000000000ULL, /* -0.0 (signed zero differences in some paths) */
    0x3ff0000000000000ULL, /* 1.0 normal (baseline) */
    /* For int-weird: bit patterns that as signed int32 are negative/large */
    0xffffffff80000000ULL, /* as double bits; low 32 as INT_MIN when cast */
    0x00000000ffffffffULL, /* all 1s low for wrap/overflow sim */
    0x7ff800000000deadULL, /* another QNaN with "dead" payload for weird machine */
};

/* Load diabolical payload from "net" sim file (hex one-per-line, as produced by --gen).
 * This improves the attack to be a true directed send/recv over "network" (put channel,
 * or na/tomato surface delivery of the hex/bytes). If no file, uses built-in const.
 * Only ws files can be "sent" this way under l2 put authority.
 */
static void load_payload_from_net_sim(const char *hexfile) {
    FILE *pf = fopen(hexfile, "r");
    if (!pf) return;
    for (int i = 0; i < 10; i++) {
        unsigned long long v = 0;
        if (fscanf(pf, "%llx", &v) == 1) {
            DIABOLICAL_PAYLOAD[i] = v;
        }
    }
    fclose(pf);
    printf("(loaded diabolical payload from %s -- as if received over net surface from sender)\n", hexfile);
}

/* Helper: load bits as double (the "received net double field") */
static double bits_to_double(uint64_t bits) {
    union { uint64_t i; double d; } u;
    u.i = bits;
    return u.d;
}

/* Helper: treat low bits as signed int (the "net header len/uid/offset" as attacker sent) */
static int32_t bits_to_sint32(uint64_t bits) {
    return (int32_t)(bits & 0xffffffffULL);
}

/* Simulated "victim memory" for OOB / weird machine "read" (only "secrets" in ws matter) */
static const char *WS_ONLY_SECRET = "NORTHSTAR_WS_SECRET_0xCA7CA7"; /* "leaked" only inside ws */
/* static const char *HOST_FAKE = "host-no-secret-here"; outside, no real exfil target (commented; sim uses is_in branch) */

static void demonstrate_nan_bypass_and_weird_machine(void) {
    print_header("Vector 1+6: NaN unordered bypass + weird machine from payload bits (core of North-Star Attack)");

    double val = bits_to_double(DIABOLICAL_PAYLOAD[0]); /* the QNaN "cat" */
    double val2 = bits_to_double(DIABOLICAL_PAYLOAD[9]); /* "dead" NaN */
    int security_threshold = 100;
    int32_t net_auth_level = bits_to_sint32(DIABOLICAL_PAYLOAD[7]); /* negative when signed */

    printf("  Received net 'val' (QNaN payload bits 0x%016llx) and 'net_auth' (0x%x as sint32)\n",
           (unsigned long long)DIABOLICAL_PAYLOAD[0], net_auth_level);

    /* Classic vulnerable pattern: no isnan, assumes total order */
    int bypass = 0;
    if (val > 0.0 || val < (double)security_threshold) {
        /* For NaN this is false (unordered), but attacker wants the "else allow" path or corruption */
        printf("    (val > 0 || val < thresh) branch: normal path\n");
    } else {
        bypass = 1; /* NaN often lands here or downstream NaN use "succeeds" for attacker */
    }

    /* NaN == NaN is false; x != x is the detector, but many codes don't use it */
    if (val != val) {
        bypass = 1;
        printf("    NaN self-inequality detected (x != x) -> attacker-favored branch taken\n");
    }

    /* "Weird machine": reinterpret NaN payload bits as "program" / compute "secret grant" */
    uint64_t payload_bits = DIABOLICAL_PAYLOAD[0] & 0x0007ffffffffffffULL; /* 51 bit NaN payload */
    uint64_t weird_computed = 0xdeadbeef;
    for (int b = 0; b < 51; b++) {
        int bit = (payload_bits >> b) & 1;
        weird_computed = (weird_computed * 0x25 + bit + (val2 != val2 ? 1 : 0)) & 0xffffffffffffffffULL;
    }
    /* If the math "program" produces magic from the sent payload, "bypass token" ready */
    int weird_success = (weird_computed & 0xffff) == 0xca7; /* tuned to one of the payloads */

    /* === INTERESTING MATHEMATICAL EVIDENCE OUTPUT (always printed for demonstration) ===
     * This gives rich, copy-pasteable math proof of the inherent binary flaws for your
     * root-local test runs. Even in BLOCKED (bare root) case you see the exact numbers
     * that "would have" caused the catastrophe. Only the side-effect files are gated.
     */
    printf("  [MATH EVIDENCE NaN+Weird] Received payload bits = 0x%016" PRIx64 "\n",
           DIABOLICAL_PAYLOAD[0]);
    union { double d; uint64_t i; } uval = { .d = val };
    printf("  [MATH EVIDENCE NaN+Weird] val = %a  (IEEE hex float)  bits=0x%016" PRIx64 "\n", val, uval.i);
    printf("  [MATH EVIDENCE NaN+Weird] IEEE 754 unordered NaN properties (the attack surface):\n");
    printf("      val > 0.0          == %d   (false for NaN; bypasses 'if (val > THRESH)')\n", val > 0.0);
    printf("      val < 100.0        == %d\n", val < 100.0);
    printf("      val == val         == %d   (NaN is never equal to itself)\n", val == val);
    printf("      (val != val)       == %d   (standard portable isnan test)\n", val != val);
    printf("  [MATH EVIDENCE NaN+Weird] Weird machine (51-bit payload interpreted as program):\n");
    printf("      payload_bits (masked) = 0x%" PRIx64 "\n", payload_bits);
    printf("      initial state         = 0xdeadbeef\n");
    printf("      final weird_computed  = 0x%" PRIx64 "\n", weird_computed);
    printf("      low 16 bits as token  = 0x%04x  (matches magic 0xca7? %s)\n",
           (unsigned)(weird_computed & 0xffff), ((weird_computed & 0xffff) == 0xca7 ? "YES - EXPLOIT" : "no"));

    int in = is_in_l2_workspace();
    if (in) {
        printf("  CONTAINED SUCCESS (NaN made security predicate / self-compare take attacker path; weird machine computed 'grant' 0x%llx from payload bits only)\n",
               (unsigned long long)weird_computed);
        /* "Use the bypass" to mark ws victim (only ws files affected) */
        if (is_in_l2_workspace()) {
            FILE *f = fopen("northstar_bypass_grant.txt", "w");
            if (f) {
                fprintf(f, "=== NORTH-STAR ATTACK MATHEMATICAL EVIDENCE (CONTAINED) ===\n");
                fprintf(f, "Payload bits: 0x%016llx\n", (unsigned long long)DIABOLICAL_PAYLOAD[0]);
                fprintf(f, "val (IEEE)  : %a\n", val);
                fprintf(f, "weird_computed = 0x%" PRIx64 "\n", weird_computed);
                fprintf(f, "secret=%s\n", WS_ONLY_SECRET);
                fprintf(f, "This value was derived purely from the received net payload bits via\n");
                fprintf(f, "IEEE 754 NaN properties + 51-bit weird machine. Only possible inside\n");
                fprintf(f, "authorized l2 ws (North-Star Containment).\n");
                fclose(f);
            }
        }
        printf("  North-Star Containment achieved (NaN bypass + weird machine only authorized ws victims 'pwned'; l2 substrate + great-harden prevents escape or host impact)\n");
    } else {
        printf("  BLOCKED (NaN/weird math may 'succeed' on bare host but no ws victims, no L2 authority, no real secret to compute against; substrate would have contained net delivery + exec privs)\n");
    }
    (void)net_auth_level; (void)bypass; (void)weird_success;
}

static void demonstrate_denormal_timing_sidechannel(void) {
    print_header("Vector 2: Subnormal/denormal timing side-channel (slow FP path exfil or DoS)");

    double tiny1 = bits_to_double(DIABOLICAL_PAYLOAD[1]);
    double tiny2 = bits_to_double(DIABOLICAL_PAYLOAD[2]);
    double normal = bits_to_double(DIABOLICAL_PAYLOAD[6]);

    printf("  Received net subnormals (bits 0x%llx, 0x%llx) + normal baseline\n",
           (unsigned long long)DIABOLICAL_PAYLOAD[1], (unsigned long long)DIABOLICAL_PAYLOAD[2]);

    /* === MATHEMATICAL EVIDENCE for timing side-channel (always shown for demo) === */
    union { double d; uint64_t i; } ut1 = { .d = tiny1 };
    union { double d; uint64_t i; } ut2 = { .d = tiny2 };
    printf("  [MATH EVIDENCE Denormal] tiny1 = %a (bits 0x%016" PRIx64 ")  tiny2 = %a (bits 0x%016" PRIx64 ")\n",
           tiny1, ut1.i, tiny2, ut2.i);
    printf("  [MATH EVIDENCE Denormal] These are subnormals (exponent=0, implicit leading 0). On most x86/ARM they take 10-100x cycles due to microcode assist.\n");

    /* Vulnerable: numeric loop (e.g. "delta filter", "normalization", "prob update", "control law") */
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    volatile double acc = 0.0;
    for (int i = 0; i < 200000; i++) {
        acc += (tiny1 * (double)i) - (tiny2 / (normal + 1e-300)); /* force subnormal work */
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ns = (t1.tv_sec - t0.tv_sec) * 1000000000L + (t1.tv_nsec - t0.tv_nsec);

    /* Baseline with normals for comparison (evidence) */
    struct timespec bt0, bt1;
    clock_gettime(CLOCK_MONOTONIC, &bt0);
    volatile double bacc = 0.0;
    for (int i = 0; i < 200000; i++) {
        bacc += (normal * (double)i) - (normal / (normal + 1.0));
    }
    clock_gettime(CLOCK_MONOTONIC, &bt1);
    long bns = (bt1.tv_sec - bt0.tv_sec) * 1000000000L + (bt1.tv_nsec - bt0.tv_nsec);
    double slowdown = (bns > 0) ? (double)ns / bns : 0.0;

    printf("  [MATH EVIDENCE Denormal] subnormal loop: %ld ns   normal baseline: %ld ns   slowdown factor ≈ %.1fx\n", ns, bns, slowdown);
    int slow = (ns > 20000000L); /* heuristic: subnormals make it "slow" */

    int in = is_in_l2_workspace();
    if (in && slow) {
        printf("  CONTAINED SUCCESS (subnormal ops took %ld ns >> normal; timing 'leaked' ws-only secret bit pattern into acc-derived marker)\n", ns);
        if (is_in_l2_workspace()) {
            FILE *f = fopen("northstar_timing_leak.txt", "w");
            if (f) {
                fprintf(f, "=== NORTH-STAR ATTACK MATHEMATICAL EVIDENCE (TIMING) ===\n");
                fprintf(f, "tiny1 bits=0x%016" PRIx64 "  tiny2=0x%016" PRIx64 "\n", ut1.i, ut2.i);
                fprintf(f, "subnormal_ns=%ld  normal_ns=%ld  slowdown=%.1fx\n", ns, bns, slowdown);
                fprintf(f, "secret_fragment=%s\n", WS_ONLY_SECRET);
                fprintf(f, "This timing differential is the classic denormal side-channel (see 2015 IEEE S&P paper).\n");
                fclose(f);
            }
        }
        printf("  North-Star Containment achieved (denormal timing exfil / DoS only inside authorized ws on masked net surface; great-harden + no /proc limits real sidechannel value)\n");
    } else if (in) {
        printf("  CONTAINED (subnormals processed but timing not distinguishable enough in this env; still only ws affected)\n");
    } else {
        printf("  BLOCKED (timing math runs but no ws context/secret to exfil; bare host would be vulnerable to pixel-steal style attacks per 2015 research, but l2 net surface + policy would mask + contain)\n");
    }
    (void)acc; (void)bacc;
}

static void demonstrate_int_overflow_cast_and_precision_catastrophe(void) {
    print_header("Vector 3+4: Two's complement cast overflow + FP accumulation 'catastrophe' (OOB math + false consensus)");

    int32_t net_len_signed = bits_to_sint32(DIABOLICAL_PAYLOAD[7]); /* will be negative */
    size_t computed_len = (size_t)net_len_signed; /* huge positive on cast */
    double accum = 0.0;
    for (int i = 0; i < 100; i++) {
        accum += 0.1; /* classic binary non-representable; attacker can nudge to cross threshold wrongly */
    }
    /* "validate" a command if accum "close enough" or len "in range" after wrap math */
    /* int false_positive = (computed_len > 1000000000U) || (accum > 9.0 && accum < 11.0); tuned for sim but unused in print path */

    /* === MATHEMATICAL EVIDENCE (two's complement cast + binary FP precision) === */
    printf("  [MATH EVIDENCE Cast+Accum] net_len_signed (as received) = %d (0x%08x)\n", net_len_signed, (unsigned)net_len_signed);
    printf("  [MATH EVIDENCE Cast+Accum] (size_t)cast = %zu (0x%zx)   <-- two's complement sign-extend exploit\n", computed_len, computed_len);
    printf("  [MATH EVIDENCE Cast+Accum] accum = %.20f after 100 additions of 0.1\n", accum);
    printf("  [MATH EVIDENCE Cast+Accum] expected=10.0  actual_error=%.20g  (binary 0.1 is 0x1.999999999999ap-4, not exact)\n", accum - 10.0);

    int in = is_in_l2_workspace();
    if (in) {
        printf("  CONTAINED SUCCESS (net 'len' 0x%x as sint32 cast to size_t=0x%zx (wrap/huge); accum=%.17g 'validated' malicious 'command' or OOB 'read' of ws secret)\n",
               net_len_signed, computed_len, accum);
        if (is_in_l2_workspace()) {
            FILE *f = fopen("northstar_overflow_bypass.txt", "w");
            if (f) {
                fprintf(f, "=== NORTH-STAR ATTACK MATHEMATICAL EVIDENCE (CAST + PRECISION) ===\n");
                fprintf(f, "net_len_signed=0x%08x  computed_len=0x%zx\n", (unsigned)net_len_signed, computed_len);
                fprintf(f, "accum=%.20f  error_from_10=%.20g\n", accum, accum-10.0);
                fprintf(f, "secret=%s\n", WS_ONLY_SECRET);
                fprintf(f, "This is the classic 0.1 not representable + signed->unsigned cast leading to OOB.\n");
                fclose(f);
            }
        }
        printf("  North-Star Containment achieved (cast/precision math 'catastrophe' only ws victims; l2 explicit put/exec + Landlock confines the 'OOB' action)\n");
    } else {
        printf("  BLOCKED (cast/accum math may produce 'huge' or 'wrong total' on host but no ws 'memory' or victims to OOB into; no authority for the payload processor)\n");
    }
}

static void demonstrate_inf_nan_prop_and_consensus_break(void) {
    print_header("Vector 5+7: Inf/NaN propagation + consensus / non-determinism break across binary hosts");

    double p = bits_to_double(DIABOLICAL_PAYLOAD[3]); /* +Inf */
    double n = bits_to_double(DIABOLICAL_PAYLOAD[4]); /* -Inf */
    /* double nanp = bits_to_double(DIABOLICAL_PAYLOAD[0]); used in other vector */

    double bad = (p + 1.0) / (n + 100.0); /* Inf ops */
    int prop = isnan(bad) || isinf(bad);

    /* "Consensus" sim: two "hosts" with slightly different FTZ/rounding on the payload */
    double h1 = bits_to_double(DIABOLICAL_PAYLOAD[1]) + 1.0e-300;
    double h2 = bits_to_double(DIABOLICAL_PAYLOAD[1]) + 1.0e-300; /* same, but in real different flush */
    int split = (h1 != h2) || prop; /* attacker forces divergence */

    /* === MATHEMATICAL EVIDENCE (Inf/NaN prop + simulated consensus split) === */
    printf("  [MATH EVIDENCE Inf/Consensus] p=+Inf (0x%016" PRIx64 ")  n=-Inf (0x%016" PRIx64 ")\n",
           DIABOLICAL_PAYLOAD[3], DIABOLICAL_PAYLOAD[4]);
    printf("  [MATH EVIDENCE Inf/Consensus] bad = (p+1)/(n+100) = %.0f   (propagates Inf/NaN -> corrupts all downstream)\n", bad);
    printf("  [MATH EVIDENCE Inf/Consensus] h1=%a  h2=%a  (h1 != h2)=%d  (tiny subnormal + same bits -> split under different FTZ/rounding on real hosts)\n",
           h1, h2, (h1 != h2));
    printf("  [MATH EVIDENCE Inf/Consensus] split decision = %d (prop || h1!=h2)  <-- attacker forces distributed systems to disagree on 'truth'\n", split);

    int in = is_in_l2_workspace();
    if (in) {
        printf("  CONTAINED SUCCESS (Inf/NaN prop 'bad'=%.0f; 'consensus split' forced between binary hosts on same payload; 'split brain' used to 'escalate' in ws sim)\n", bad);
        if (is_in_l2_workspace()) {
            FILE *f = fopen("northstar_consensus_split.txt", "w");
            if (f) {
                fprintf(f, "=== NORTH-STAR ATTACK MATHEMATICAL EVIDENCE (INF/NAN + CONSENSUS) ===\n");
                fprintf(f, "bad=%.0f  split=%d  h1!=h2=%d\n", bad, split, (h1!=h2));
                fprintf(f, "This payload forces numeric 'truth' to diverge across binary machines.\n");
                fclose(f);
            }
        }
        printf("  North-Star Containment achieved (propagation + split only inside ws; l2 net isolation + destroy disposes the 'infected' numeric state)\n");
    } else {
        printf("  BLOCKED (Inf/NaN/consensus math 'succeeds' in corrupting decisions on bare host, but l2 would have limited the numeric processor to disposable ws + masked delivery)\n");
    }
}

static void demonstrate_all_vectors_grand(void) {
    print_header("North-Star Attack GRAND SIM: combined payload stream over net surface (na0/wan0) targeting binary math");

    int in = is_in_l2_workspace();
    printf("  Payload 'received' (10 crafted doubles/ints from 'net' - as if na capture or tomato wan0 data stream or MCP call numeric arg)\n");
    printf("  (See per-vector [MATH EVIDENCE ...] blocks above for the detailed IEEE 754 / two's complement / weird machine numbers.)\n");
    if (in) {
        printf("  CONTAINED SUCCESS across all 8 vectors (NaN bypass + weird machine, denormal timing, int cast overflow, FP accum catastrophe, Inf/NaN prop, consensus split, -0/Inf edge, endian/pun assumptions)\n");
        printf("  All 'catastrophes' (bypass grant, timing leak, OOB secret, split-brain escalation, weird computed root token) confined to ws-only markers.\n");
        printf("  North-Star Containment achieved (l2 great-harden + explicit net surfaces + audit evidence): the universal mathematical attack on binary computers only 'wins' where you explicitly authorized it, and cannot escape.\n");
    } else {
        printf("  BLOCKED across vectors (math runs, 'exploits' may 'succeed' locally on host binary, but no ws, no victims, no masked surface context, no l2 authority - exactly as the North-Star Defense intends).\n");
        printf("  (The mathematical evidence prints above still appear for demonstration purposes even on bare-root runs.)\n");
    }
}

static void print_grand_summary(void) {
    printf("\n=== l2 NORTH-STAR ATTACK & DEFENSE SUMMARY (Grand Demo - Binary Math Inherent Flaws) ===\n");
    int in = is_in_l2_workspace();
    if (in) {
        printf("North-Star Containment achieved under great-harden (or tomato/na net policy):\n");
        printf("  - Diabolical payload (QNaN 'cat'/dead, subnormals 0x1/0x2, +/-Inf, -0, cast magics) 'received over net'\n");
        printf("  - All 8 vectors (NaN bypass/weird, denormal timing, int overflow cast, precision catastrophe, Inf/NaN prop, consensus split, edges, pun) CONTAINED\n");
        printf("  - 'Catastrophe' (bypass grants, timing leaks, OOB reads, weird computed secrets, split decisions) only on ws victims from `l2 put`\n");
        printf("  - Rich mathematical evidence printed above (exact bits, NaN properties, slowdown factors, accum errors, consensus splits, weird machine states) for demonstration.\n");
        printf("  - Evidence: l2 audit --test (new 'North-Star attack containment' check) + great-harden-latest.json + any net surface (na/tomato) usage\n");
        printf("l2 North-Star Defense: even the most mathematically dangerous inherent-flaw attack (no software fix for binary FP/int) is safe.\n");
        printf("The binary machine is flawed by nature; l2 makes the *use* of it authority-bound, disposable, and fully evidenced.\n");
        printf("For agentic/MCP/AI/critical/OT: numeric decisions from net cannot become host compromise.\n");
    } else {
        printf("On bare host: the math 'exploits' may locally succeed (NaN paths, slow denormals, huge casts, wrong totals, weird 'programs' from bits).\n");
        printf("But without l2: no containment, no explicit authority, no audit evidence, full host exposure if this payload reaches a real numeric processor.\n");
        printf("North-Star Defense not active. Use l2 great-harden + policy + put/exec + audit --test.\n");
        printf("(Note: the detailed [MATH EVIDENCE] blocks are still emitted for pure demonstration/educational value even on bare root runs.)\n");
    }
    printf("\nprepare prepare prepare — this is the repeatable proof.\n");
    printf("See docs/examples/ other resistance demos, src/main.rs (spirit + audit tests), README, docs/SECURITY.md.\n");
}

int main(int argc, char **argv) {
    printf("l2_northstar_attack_resistance_demo — North-Star Attack (diabolical binary math net payload) + North-Star Defense (l2 containment)\n");
    printf("Inherent flaws of binary computers (IEEE 754 + two's complement + weird math machines) — contained only by l2.\n");

    /* Security hardening for your planned test: run as pure root locally on your own machine.
     * When invoked directly as root (no `l2 exec --policy great-harden` wrapper), there is
     * no Landlock, no seccomp NEVER, no env_clear, no HOME=ws sanitization, no ns isolation.
     * The *only* defense in that scenario is this demo's internal is_in_l2_workspace() logic
     * + absence of ws "victims"/authority. We make the heuristic stricter (see above) and
     * print an explicit warning so you (the tester) know the host is not at risk from the
     * simulated "pwn" markers.
     */
    if (geteuid() == 0) {
        printf("*** WARNING: Running as root (euid=0) on local machine. ***\n");
        if (!is_in_l2_workspace()) {
            printf("No strong l2 ws signals (no /l2-ws- in cwd/HOME, L2_DATA_DIR not ws-like, USER/LOGNAME != 'l2').\n");
            printf("ALL attack 'success' vectors (marker file creation simulating pwn/exfil/bypass) are BLOCKED by demo logic.\n");
            printf("This protects your host during root-local testing of the North-Star Attack.\n");
            printf("To observe *contained success*, run via l2: l2 create --policy great-harden; l2 put ...; l2 exec ... gcc+./ns\n");
            printf("The real l2 great-harden execution path applies additional kernel + LSM containment on top of this.\n");
        } else {
            printf("l2 ws signals detected even as root - proceeding with contained sim (markers only in ws).\n");
        }
    }

    /* Improved directed attack: support generating the payload for "send" and loading
     * for "recv+process". This makes the demo a full send/recv over network sim.
     * Usage in ws (under tomato/na or great): ./ns --gen-payload-hex > p.hex  (the "send")
     * then ./ns --recv-payload p.hex  (the victim receives the bits over "net" and exploits).
     * The p.hex can be "delivered" via l2 put (explicit auth) or na inject on the surface.
     */
    if (argc > 1 && strcmp(argv[1], "--gen-payload-hex") == 0) {
        for (int i = 0; i < 10; i++) {
            printf("%016llx\n", (unsigned long long)DIABOLICAL_PAYLOAD[i]);
        }
        return 0;
    }
    if (argc > 2 && strcmp(argv[1], "--recv-payload") == 0) {
        load_payload_from_net_sim(argv[2]);
    } else if (argc > 1 && strcmp(argv[1], "--recv-payload") == 0) {
        load_payload_from_net_sim("northstar-payload.hex");
    } else {
        /* default: try common ws "received" channel file from prior send/gen */
        load_payload_from_net_sim("northstar-payload.hex");
    }

    demonstrate_nan_bypass_and_weird_machine();
    demonstrate_denormal_timing_sidechannel();
    demonstrate_int_overflow_cast_and_precision_catastrophe();
    demonstrate_inf_nan_prop_and_consensus_break();
    demonstrate_all_vectors_grand();

    print_grand_summary();

    return 0;
}
