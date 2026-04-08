CC = gcc
CFLAGS = -Wall

all:
	$(CC) main.c monitor.c entropy.c logger.c -o detector -lm

clean:
	rm -f detector
