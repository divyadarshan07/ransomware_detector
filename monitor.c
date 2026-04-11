#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <time.h>
#include "monitor.h"
#include "entropy.h"
#include "logger.h"

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))

int modification_count = 0;
time_t start_time;

/* ── Full-screen terminal alert ── */
void show_fullscreen_alert(const char *reason) {
    /* Clear screen, set red background, white bold text */
    printf("\033[2J\033[H");                   /* clear + move cursor to top-left  */
    printf("\033[41;97;1m");                   /* red BG, bright-white bold FG     */

    /* Fill every line so the whole terminal is red */
    int rows = 40, cols = 120;                 /* safe fallback dimensions          */

    /* Try to read actual terminal size via tput */
    FILE *rp = popen("tput lines 2>/dev/null", "r");
    FILE *cp = popen("tput cols  2>/dev/null", "r");
    if (rp) { fscanf(rp, "%d", &rows); pclose(rp); }
    if (cp) { fscanf(cp, "%d", &cols); pclose(cp); }

    /* Print blank red lines to fill the screen */
    for (int r = 0; r < rows; r++) {
        for (int c = 0; c < cols; c++) printf(" ");
        printf("\n");
    }

    /* Move to vertical center */
    printf("\033[%d;1H", rows / 2 - 3);

    /* Banner */
    int pad = (cols - 54) / 2; if (pad < 0) pad = 0;
    for (int i = 0; i < pad; i++) printf(" ");
    printf("██████╗  █████╗ ███╗  ██╗███████╗ ██████╗ ███╗  ███╗\n");

    for (int i = 0; i < pad; i++) printf(" ");
    printf("██╔══██╗██╔══██╗████╗ ██║██╔════╝██╔═══██╗████╗████║\n");

    for (int i = 0; i < pad; i++) printf(" ");
    printf("██████╔╝███████║██╔██╗██║███████╗██║   ██║██╔████╔██║\n");

    for (int i = 0; i < pad; i++) printf(" ");
    printf("██╔══██╗██╔══██║██║╚████║╚════██║██║   ██║██║╚██╔╝██║\n");

    for (int i = 0; i < pad; i++) printf(" ");
    printf("██║  ██║██║  ██║██║ ╚███║███████║╚██████╔╝██║ ╚═╝ ██║\n");

    for (int i = 0; i < pad; i++) printf(" ");
    printf("╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝\n\n");

    /* ── DETECTED heading ── */
    const char *heading = "🚨  RANSOMWARE DETECTED  🚨";
    int hlen = 28;  /* visible char width (emoji counts as 2) */
    pad = (cols - hlen) / 2; if (pad < 0) pad = 0;
    for (int i = 0; i < pad; i++) printf(" ");
    printf("\033[5m%s\033[25m\n\n", heading);   /* blinking text */

    /* ── Reason ── */
    int rlen = (int)strlen(reason);
    pad = (cols - rlen) / 2; if (pad < 0) pad = 0;
    for (int i = 0; i < pad; i++) printf(" ");
    printf("Reason : %s\n\n", reason);

    /* ── Timestamp ── */
    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    const char *tslabel = "Time   : ";
    int tslen = (int)(strlen(tslabel) + strlen(ts));
    pad = (cols - tslen) / 2; if (pad < 0) pad = 0;
    for (int i = 0; i < pad; i++) printf(" ");
    printf("%s%s\n\n", tslabel, ts);

    /* ── Instructions ── */
    const char *instr = "ACTION REQUIRED: Isolate this machine immediately!";
    pad = (cols - (int)strlen(instr)) / 2; if (pad < 0) pad = 0;
    for (int i = 0; i < pad; i++) printf(" ");
    printf("%s\n", instr);

    /* ── Reset colours and flush ── */
    printf("\033[0m");
    fflush(stdout);

    /* Keep alert visible for 10 seconds, then restore normal output */
    sleep(10);

    /* Restore clean screen for continued monitoring */
    printf("\033[2J\033[H");
    printf("🛡️  Ransomware Detector — continuing to monitor...\n\n");
    fflush(stdout);
}

void check_ransomware(const char *filename) {
    /* Build full path relative to monitored dir if needed */
    char filepath[4096];
    snprintf(filepath, sizeof(filepath), "%s", filename);

    double entropy = calculate_entropy(filepath);

    if (entropy > 7.5) {
        char msg[512];
        snprintf(msg, sizeof(msg),
                 "High entropy (%.2f) on file: %s — possible encryption", entropy, filename);
        log_alert(msg);
        show_fullscreen_alert("High file entropy — file may be encrypted by ransomware");
    }
}

void start_monitoring(const char *path) {
    int fd, wd;
    char buffer[BUF_LEN];

    fd = inotify_init();
    if (fd < 0) {
        perror("inotify_init");
        exit(1);
    }

    wd = inotify_add_watch(fd, path, IN_MODIFY | IN_CREATE | IN_MOVED_TO);
    if (wd < 0) {
        perror("inotify_add_watch");
        exit(1);
    }

    start_time = time(NULL);
    printf("👁️  Watching: %s\n\n", path);
    fflush(stdout);

    while (1) {
        int length = read(fd, buffer, BUF_LEN);
        if (length < 0) {
            perror("read");
            break;
        }

        for (int i = 0; i < length;) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];

            if (event->len) {
                /* Build full file path */
                char filepath[4096];
                snprintf(filepath, sizeof(filepath), "%s/%s", path, event->name);

                if (event->mask & IN_MODIFY) {
                    modification_count++;
                    printf("✏️  Modified : %s\n", event->name);
                    fflush(stdout);
                    check_ransomware(filepath);
                }

                if (event->mask & IN_CREATE) {
                    printf("➕ Created  : %s\n", event->name);
                    fflush(stdout);
                }

                if (event->mask & IN_MOVED_TO) {
                    printf("🔀 Renamed  : %s\n", event->name);
                    fflush(stdout);
                    log_alert("File rename detected (possible ransomware)");
                    show_fullscreen_alert("Suspicious file rename — classic ransomware behaviour");
                }
            }

            i += EVENT_SIZE + event->len;
        }

        /* Check modification rate — too many changes in 5 seconds */
        double elapsed = difftime(time(NULL), start_time);
        if (elapsed <= 5.0) {
            if (modification_count > 10) {
                log_alert("Too many file modifications in short time!");
                show_fullscreen_alert("Mass file modification detected — rapid encryption in progress");
                modification_count = 0;
                start_time = time(NULL);
            }
        } else {
            modification_count = 0;
            start_time = time(NULL);
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
}
