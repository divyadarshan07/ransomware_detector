#include <stdio.h>
#include <time.h>
#include "logger.h"

void log_alert(const char *message) {
    FILE *log = fopen("alerts.log", "a");
    if (!log) return;

    time_t now = time(NULL);
    fprintf(log, "%s - %s\n", ctime(&now), message);

    fclose(log);
}
