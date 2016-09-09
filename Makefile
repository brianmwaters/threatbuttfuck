SH = /bin/sh

.PREFIX:
.PREFIX: .o .c

CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wformat-security -D_XOPEN_SOURCE=700 -D_FORTIFY_SOURCE=2 -O3 -flto -fPIE -fstack-protector-all -fstack-check -ftrapv
LDFLAGS = -pie -flto -fPIE -Wl,-s -Wl,-z,relro -Wl,-z,now

TARGETS = threatbuttfuck

.PHONY: all
all : $(TARGETS)

% : %.o
	$(CC) $(LDFLAGS) $^ -o $@

%.o : %.c
	$(CC) -c $(CFLAGS) $^ -o $@

.PHONY: clean
clean :
	rm -rf $(TARGETS) *.o
