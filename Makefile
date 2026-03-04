PACKAGE = pkt_monitor
CC      = cc
CFLAGS  = -O2 -g -Wall -Wextra -Werror
LDFLAGS = -lpcap

SRCS = pkt_monitor.c
OBJS = $(SRCS:.c=.o)

all: $(PACKAGE)

$(PACKAGE): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(PACKAGE) $(OBJS)

install: $(PACKAGE)
	install -m 755 $(PACKAGE) /usr/local/bin/

.PHONY: all clean install
