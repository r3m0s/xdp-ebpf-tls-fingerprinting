CC      = gcc
CFLAGS  = -O2 -Wall -Wextra
LDFLAGS = -lssl -lcrypto

TARGETS = string2ja3 string2ja4

all: $(TARGETS)

# Build
string2ja3: string2ja3.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

string2ja4: string2ja4.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:

mrproper: clean
	rm -f *.o