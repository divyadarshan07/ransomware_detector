#include <stdio.h>
#include <math.h>

double calculate_entropy(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) return 0;

    int freq[256] = {0};
    int total = 0;
    unsigned char buffer[1024];

    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        for (int i = 0; i < bytesRead; i++) {
            freq[buffer[i]]++;
            total++;
        }
    }

    fclose(file);

    double entropy = 0.0;

    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;

        double p = (double)freq[i] / total;
        entropy -= p * log2(p);
    }

    return entropy;
}
