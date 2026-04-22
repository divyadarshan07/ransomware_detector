#include <stdio.h>
#include <time.h>
#include "logger.h"

void log_alert(const char *message) {
    FILE *log = fopen("alerts.log", "a");
    if (!log) return;

    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(log, "%s - %s\n", ts, message);

    fclose(log);
}
