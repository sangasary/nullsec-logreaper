CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11
LDFLAGS =
TARGET = logreaper
SRC = src/main.c
PREFIX = /usr/local

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@printf "\n  🪓 LogReaper built successfully!\n  Run: ./$(TARGET) --help\n\n"

clean:
	rm -f $(TARGET) *.o

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET)
