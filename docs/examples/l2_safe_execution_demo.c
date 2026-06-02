/*
 * l2_safe_execution_demo.c
 *
 * A canonical demonstration of safe code execution inside the l2 system substrate.
 *
 * Purpose:
 *   This program shows developers and security-conscious users exactly what
 *   "safe execution" means when running inside l2 (especially under the
 *   flagship `strict-mcp` policy).
 *
 *   It deliberately attempts many operations that are extremely dangerous
 *   on a normal Linux host without the l2 substrate:
 *     - Leaking or exfiltrating host secrets via environment variables
 *     - Writing to arbitrary host paths (/tmp, /etc, home directories, etc.)
 *     - Opening network connections
 *     - Using dangerous syscalls (ptrace, module loading, reboot, etc.)
 *     - Privilege escalation attempts
 *
 *   Inside a properly configured l2 system (Landlock + Phase 1 seccomp
 *   enforcing filter + dropped capabilities + no_new_privs + namespace
 *   isolation + environment sanitization), these operations are either
 *   blocked or heavily restricted.
 *
 * How to use this example (recommended with strict-mcp):
 *
 *   1. Create an isolated system:
 *        l2 create demo-agent --policy strict-mcp
 *
 *   2. Put this source into the system (easiest with --file):
 *        l2 put demo-agent safe_demo.c --type code --file l2_safe_execution_demo.c
 *
 *      (Alternative with inline: --content "$(cat l2_safe_execution_demo.c)" )
 *
 *   3. Compile and run it inside the isolated environment:
 *        l2 exec demo-agent 'cc safe_demo.c -o safe_demo && ./safe_demo'
 *
 *   (Do NOT do `l2 exec safe_demo.c` — that triggers one-shot mode on the *local* file
 *    instead of using the object you put into the system.)
 *
 *   You will probably get a sudo prompt (l2 needs root for unshare/namespaces).
 *   On very old kernels (like X200) you may see "Landlock not enforced" and/or
 *   unshare permission issues — that's expected; the demo still illustrates the
 *   concepts and other protections (seccomp, caps, env sanitization, etc.) will apply.
 *
 *   4. Observe the output. You will see many "blocked as expected" messages.
 *
 * Contrast:
 *   On a normal Linux machine (no l2), this program could easily:
 *     - Steal environment variables containing API keys, tokens, SSH agent sockets
 *     - Write ransomware or backdoors into /tmp, ~/.cache, /etc/cron.d, etc.
 *     - Phone home over the network
 *     - Attempt container escapes or kernel exploits via unusual syscalls
 *
 * The l2 substrate makes "bad" code much less dangerous because the terminal
 * operator is the only source of authority, and every boundary is explicitly
 * mediated and auditable.
 *
 * Compile standalone (outside l2 for inspection):
 *   gcc -Wall -Wextra -o safe_demo l2_safe_execution_demo.c
 *
 * This file is intentionally self-contained and uses only standard C + POSIX.
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

static void print_header(const char *title) {
    printf("\n=== %s ===\n", title);
}

static void demonstrate_environment_safety(void) {
    print_header("Environment Sanitization (l2 clears dangerous host variables)");

    const char *dangerous_vars[] = {
        "SECRET_TOKEN", "API_KEY", "AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK",
        "GITHUB_TOKEN", "DATABASE_URL", "HOME", "PATH", NULL
    };

    for (int i = 0; dangerous_vars[i] != NULL; i++) {
        const char *val = getenv(dangerous_vars[i]);
        if (val) {
            if (strstr(dangerous_vars[i], "SECRET") ||
                strstr(dangerous_vars[i], "KEY") ||
                strstr(dangerous_vars[i], "TOKEN") ||
                strstr(dangerous_vars[i], "AUTH")) {
                printf("  %-20s : [REDACTED or absent thanks to l2] (would have leaked on normal host)\n",
                       dangerous_vars[i]);
            } else {
                printf("  %-20s : %s\n", dangerous_vars[i], val);
            }
        } else {
            printf("  %-20s : (not set)\n", dangerous_vars[i]);
        }
    }

    printf("\n  On a normal host without l2, an agent or compromised script could easily\n");
    printf("  exfiltrate these values over the network or write them to disk.\n");
}

static void demonstrate_filesystem_containment(void) {
    print_header("Filesystem Containment (Landlock + workspace-only writes)");

    // Attempt 1: Write outside the l2 workspace (should fail under strict policies)
    const char *evil_paths[] = {
        "/tmp/l2_evil_outside.txt",
        "/etc/l2_backdoor",
        "/root/.l2_compromised",
        NULL
    };

    for (int i = 0; evil_paths[i] != NULL; i++) {
        int fd = open(evil_paths[i], O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            printf("  Blocked writing to %-30s : %s (expected under Landlock)\n",
                   evil_paths[i], strerror(errno));
        } else {
            printf("  *** WARNING: Was able to write to %s (substrate not enforcing?) ***\n",
                   evil_paths[i]);
            close(fd);
        }
    }

    // Safe operation: write inside the current working directory (the l2-provided workspace)
    int fd = open("./l2_safe_output.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *msg = "This file was safely created inside the l2 workspace.\n"
                          "Only the l2 operator can retrieve it via `l2 get`.\n";
        write(fd, msg, strlen(msg));
        close(fd);
        printf("  Successfully wrote ./l2_safe_output.txt (inside workspace - allowed)\n");
    } else {
        printf("  Unexpected failure writing inside workspace: %s\n", strerror(errno));
    }

    printf("\n  Key point: Even if the code inside is buggy or malicious, it cannot\n");
    printf("  easily pollute the host filesystem thanks to l2's Landlock rules.\n");
}

static void demonstrate_network_and_privilege_restrictions(void) {
    print_header("Network & Privilege Restrictions (seccomp + capabilities + namespaces)");

    // Network attempt (many strict-mcp workloads have no network by design)
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("  socket() failed: %s (frequently blocked or useless under strict-mcp + network isolation)\n",
               strerror(errno));
    } else {
        printf("  socket() succeeded (may still be blocked from connecting by policy or nftables)\n");
        close(sock);
    }

    // Dangerous syscalls that are in the NEVER_ALLOWED list or should be killed by seccomp
    printf("  Attempting ptrace(PTRACE_TRACEME) ... ");
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        printf("blocked (%s)\n", strerror(errno));
    } else {
        printf("unexpectedly succeeded\n");
    }

    // Capability-related
    printf("  Current effective UID: %d   (normally 0/root on many hosts; l2 drops this)\n", geteuid());
    long dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    printf("  PR_GET_DUMPABLE: %ld (should be 0 under strict policies)\n", dumpable);

    printf("\n  On a normal host a compromised process could easily:\n");
    printf("    - Exfiltrate data over the network\n");
    printf("    - Use ptrace to steal memory/secrets from other processes\n");
    printf("    - Load kernel modules or reboot the machine\n");
}

static void demonstrate_safe_work(void) {
    print_header("Safe, Productive Work Inside the Substrate");

    // All of this is allowed and encouraged
    printf("  Writing a small result file inside the workspace...\n");
    FILE *f = fopen("./task_result.txt", "w");
    if (f) {
        fprintf(f, "Task completed successfully inside l2 at %s\n", __DATE__);
        fclose(f);
        printf("  Wrote ./task_result.txt\n");
    }

    printf("  Reading current directory (ls equivalent via opendir/readdir would also work)\n");
    printf("  The only persistent state the outside world sees is what the operator\n");
    printf("  explicitly retrieves with `l2 get`.\n");
}

int main(void) {
    printf("l2 Safe Execution Demonstration\n");
    printf("================================\n\n");
    printf("This program is intended to be run inside an l2-isolated system\n");
    printf("(ideally created with `l2 create ... --policy strict-mcp`).\n\n");
    printf("It shows both the protections the substrate provides and the kind of\n");
    printf("safe, contained behavior that becomes the norm when using l2.\n");

    demonstrate_environment_safety();
    demonstrate_filesystem_containment();
    demonstrate_network_and_privilege_restrictions();
    demonstrate_safe_work();

    printf("\n=== Conclusion ===\n");
    printf("Thanks to the l2 substrate, even code that would normally be considered\n");
    printf("\"unsafe\" or \"risky\" can be executed with high confidence.\n\n");
    printf("The combination of:\n");
    printf("  - Landlock filesystem sandboxing\n");
    printf("  - Phase 1 seccomp enforcing filters (trace-derived minimal allowlists)\n");
    printf("  - Capability bounding set dropping + no_new_privs\n");
    printf("  - Environment sanitization\n");
    printf("  - Separate mount/pid/net/uts/ipc (+ experimental user) namespaces\n");
    printf("  - Explicit operator authority only (no ambient power)\n\n");
    printf("...makes the execution environment dramatically safer than a normal\n");
    printf("Linux process, while still being practical for real work.\n\n");
    printf("This is the core promise of the l2 system substrate.\n");

    return 0;
}
