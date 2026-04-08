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

void check_ransomware(const char *filename) {
    double entropy = calculate_entropy(filename);

    if (entropy > 7.5) {
        log_alert("⚠️ High entropy detected (Possible encryption)");
        printf("⚠️ ALERT: %s has high entropy (%.2f)\n", filename, entropy);
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

    start_time = time(NULL);

    while (1) {
        int length = read(fd, buffer, BUF_LEN);

        for (int i = 0; i < length;) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];

            if (event->len) {
                if (event->mask & IN_MODIFY) {
                    modification_count++;
                    printf("Modified: %s\n", event->name);

                    check_ransomware(event->name);
                }

                if (event->mask & IN_CREATE) {
                    printf("Created: %s\n", event->name);
                }

                if (event->mask & IN_MOVED_TO) {
                    printf("Renamed/Moved: %s\n", event->name);
                    log_alert("⚠️ File rename detected (Possible ransomware)");
                }
            }

            i += EVENT_SIZE + event->len;
        }

        // Check modification rate
        if (difftime(time(NULL), start_time) <= 5) {
            if (modification_count > 10) {
                log_alert("⚠️ Too many file modifications in short time!");
                printf("🚨 ALERT: Possible ransomware activity!\n");
            }
        } else {
            modification_count = 0;
            start_time = time(NULL);
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
}
