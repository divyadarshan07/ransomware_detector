#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <sys/time.h>
#include <linux/limits.h>
#include "monitor.h"
#include "entropy.h"
#include "logger.h"

#define EVENT_SIZE  (sizeof(struct inotify_event))
#define BUF_LEN     (1024 * (EVENT_SIZE + NAME_MAX + 1))

static int    modification_count = 0;
static time_t window_start;

static void get_term_size(int *rows, int *cols) {
    struct winsize ws;
    *rows = 24;
    *cols = 80;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        if (ws.ws_row > 0) *rows = ws.ws_row;
        if (ws.ws_col > 0) *cols = ws.ws_col;
    }
}

static void show_fullscreen_alert(const char *reason) {
    int rows, cols;
    get_term_size(&rows, &cols);

    printf("\033[2J\033[H\033[41;97;1m");

    for (int r = 0; r < rows; r++) {
        for (int c = 0; c < cols; c++) putchar(' ');
        putchar('\n');
    }

    char pad_buf[512];
    int crow = rows / 2 - 5;
    if (crow < 1) crow = 1;
    printf("\033[%d;1H", crow);

    const char *banner[] = {
        " ██████╗  █████╗ ███╗  ██╗███████╗ ██████╗ ███╗  ███╗ ",
        " ██╔══██╗██╔══██╗████╗ ██║██╔════╝██╔═══██╗████╗████║ ",
        " ██████╔╝███████║██╔██╗██║███████╗██║   ██║██╔████╔██║ ",
        " ██╔══██╗██╔══██║██║╚████║╚════██║██║   ██║██║╚██╔╝██║ ",
        " ██║  ██║██║  ██║██║ ╚███║███████║╚██████╔╝██║ ╚═╝ ██║ ",
        " ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝ ",
    };
    int nlines = (int)(sizeof(banner) / sizeof(banner[0]));
    for (int l = 0; l < nlines; l++) {
        int blen = (int)strlen(banner[l]);
        int lpad = (cols - blen) / 2;
        if (lpad < 0) lpad = 0;
        memset(pad_buf, ' ', (size_t)lpad);
        pad_buf[lpad] = '\0';
        printf("%s%s\n", pad_buf, banner[l]);
    }

    const char *heading = "*** RANSOMWARE DETECTED ***";
    int hlen = (int)strlen(heading);
    int hpad = (cols - hlen) / 2;
    if (hpad < 0) hpad = 0;
    memset(pad_buf, ' ', (size_t)hpad);
    pad_buf[hpad] = '\0';
    printf("\n%s\033[5m%s\033[25m\n\n", pad_buf, heading);

    int rlen = (int)strlen(reason) + 10;
    int rpad = (cols - rlen) / 2;
    if (rpad < 0) rpad = 0;
    memset(pad_buf, ' ', (size_t)rpad);
    pad_buf[rpad] = '\0';
    printf("%sReason : %s\n\n", pad_buf, reason);

    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    int tlen = (int)strlen(ts) + 9;
    int tpad = (cols - tlen) / 2;
    if (tpad < 0) tpad = 0;
    memset(pad_buf, ' ', (size_t)tpad);
    pad_buf[tpad] = '\0';
    printf("%sTime   : %s\n\n", pad_buf, ts);

    const char *instr = "!!! ACTION REQUIRED: Isolate this machine immediately !!!";
    int ilen = (int)strlen(instr);
    int ipad = (cols - ilen) / 2;
    if (ipad < 0) ipad = 0;
    memset(pad_buf, ' ', (size_t)ipad);
    pad_buf[ipad] = '\0';
    printf("%s\033[1m%s\033[0m\n", pad_buf, instr);

    printf("\033[0m");
    fflush(stdout);

    sleep(10);

    printf("\033[2J\033[H");
    printf("[*] Ransomware Detector -- continuing to monitor...\n\n");
    fflush(stdout);
}

static void check_entropy(const char *filepath, const char *name) {
    double entropy = calculate_entropy(filepath);
    printf("    entropy=%.2f  file=%s\n", entropy, name);
    fflush(stdout);

    if (entropy > 7.5) {
        char msg[5120];
        snprintf(msg, sizeof(msg), "High entropy %.2f on: %s", entropy, filepath);
        log_alert(msg);
        show_fullscreen_alert(
            "High file entropy -- file is likely encrypted by ransomware");
    }
}

static void ensure_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) return;
    if (mkdir(path, 0755) != 0) {
        perror("mkdir");
        fprintf(stderr, "Could not create watch directory: %s\n", path);
        exit(1);
    }
    printf("[*] Created watch directory: %s\n", path);
}

void start_monitoring(const char *path) {

    ensure_dir(path);

    int fd = inotify_init();
    if (fd < 0) {
        perror("inotify_init");
        exit(1);
    }

    int wd = inotify_add_watch(fd, path,
                               IN_MODIFY     | IN_CREATE    |
                               IN_MOVED_FROM | IN_MOVED_TO  |
                               IN_DELETE);
    if (wd < 0) {
        perror("inotify_add_watch");
        fprintf(stderr, "Path tried: %s\n", path);
        close(fd);
        exit(1);
    }

    window_start = time(NULL);
    printf("[*] Watching  : %s\n", path);
    printf("[*] Thresholds: entropy > 7.5  |  modifications > 10 in 5s\n\n");
    fflush(stdout);

    char buffer[BUF_LEN];

    while (1) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        struct timeval tv;
        tv.tv_sec  = 1;
        tv.tv_usec = 0;

        int ready = select(fd + 1, &rfds, NULL, NULL, &tv);

        if (ready < 0) {
            perror("select");
            break;
        }

        double elapsed = difftime(time(NULL), window_start);
        if (elapsed > 5.0) {
            modification_count = 0;
            window_start = time(NULL);
        } else if (modification_count > 10) {
            log_alert("Too many file modifications in short time!");
            show_fullscreen_alert(
                "Mass file modification in 5s -- rapid encryption in progress");
            modification_count = 0;
            window_start = time(NULL);
        }

        if (ready == 0) continue;

        ssize_t length = read(fd, buffer, BUF_LEN);
        if (length < 0) {
            perror("read inotify");
            break;
        }

        for (ssize_t i = 0; i < length; ) {
            struct inotify_event *event =
                (struct inotify_event *)(buffer + i);

            if (event->len > 0) {
                char filepath[4096];
                snprintf(filepath, sizeof(filepath), "%s/%s", path, event->name);

                if (event->mask & IN_MODIFY) {
                    modification_count++;
                    printf("[MODIFY]       %s  (window count: %d)\n",
                           event->name, modification_count);
                    fflush(stdout);
                    check_entropy(filepath, event->name);
                }
                if (event->mask & IN_CREATE) {
                    printf("[CREATE]       %s\n", event->name);
                    fflush(stdout);
                }
                if (event->mask & IN_DELETE) {
                    printf("[DELETE]       %s\n", event->name);
                    fflush(stdout);
                }
                if (event->mask & IN_MOVED_FROM) {
                    printf("[RENAME-from]  %s\n", event->name);
                    fflush(stdout);
                }
                if (event->mask & IN_MOVED_TO) {
                    printf("[RENAME-to]    %s\n", event->name);
                    fflush(stdout);
                    log_alert("File rename detected (possible ransomware)");
                    show_fullscreen_alert(
                        "Suspicious file rename -- classic ransomware behaviour");
                }
            }

            i += (ssize_t)(EVENT_SIZE + event->len);
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
}
