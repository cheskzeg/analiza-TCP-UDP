CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpcap -lhpdf -lm

all: analyzer

analyzer: analyzer.c
	$(CC) $(CFLAGS) -o analyzer analyzer.c $(LDFLAGS)

clean:
	rm -f analyzer *.csv *.gp *.png *.pdf
