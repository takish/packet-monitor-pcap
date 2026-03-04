PACKAGE = pkt_monitor
CC      = cc
CFLAGS  = -O2 -g -Wall -Wextra -Werror
LDFLAGS = -lpcap
PREFIX ?= /usr/local

SRCS = pkt_monitor.c output.c stats.c
OBJS = $(SRCS:.c=.o)

# Auto-detect ncurses
HAS_NCURSES := $(shell echo 'int main(){return 0;}' | \
    $(CC) -x c - -lncurses -o /dev/null 2>/dev/null && echo 1)

ifeq ($(HAS_NCURSES),1)
  CFLAGS  += -DHAS_NCURSES
  LDFLAGS += -lncurses
  SRCS    += tui.c
endif

all: $(PACKAGE)
	@if [ "$(HAS_NCURSES)" = "1" ]; then \
		echo "Built with ncurses TUI support (-u flag)"; \
	else \
		echo "Built without ncurses (TUI unavailable)"; \
	fi

$(PACKAGE): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c pkt_monitor.h
	$(CC) $(CFLAGS) -c $<

tui.o: tui.c tui.h pkt_monitor.h
	$(CC) $(CFLAGS) -c $<

output.o: output.c output.h pkt_monitor.h
	$(CC) $(CFLAGS) -c $<

stats.o: stats.c stats.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(PACKAGE) $(OBJS) tui.o

install: $(PACKAGE)
	install -d $(PREFIX)/bin
	install -m 755 $(PACKAGE) $(PREFIX)/bin/

.PHONY: all clean install
