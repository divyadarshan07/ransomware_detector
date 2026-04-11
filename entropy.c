#include <stdio.h>
#include <math.h>

double calculate_entropy(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) return 0;

    long long freq[256] = {0};
    long long total = 0;
    unsigned char buffer[4096];

    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        for (size_t i = 0; i < bytesRead; i++) {
            freq[buffer[i]]++;
            total++;
        }
    }

    fclose(file);

    double entropy = 0.0;

    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / (double)total;
        entropy -= p * log2(p);
    }

    return entropy;
}
