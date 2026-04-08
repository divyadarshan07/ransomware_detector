#include <stdio.h>
#include "monitor.h"

int main() {
    printf("🛡️ Ransomware Detector Started...\n");
    start_monitoring("./test_dir");  // change folder here
    return 0;
}
