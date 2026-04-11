CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -O2

all: detector

detector: main.c monitor.c entropy.c logger.c
	$(CC) $(CFLAGS) -o detector main.c monitor.c entropy.c logger.c -lm

clean:
	rm -f detector alerts.log
