#include <stdio.h>
#include "monitor.h"

int main() {
    printf("Ransomware Detector Started...\n");
    start_monitoring("/home/kali/test_dir");
    return 0;
}
