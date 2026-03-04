/*
 * tui.h - ncurses TUI interface
 */

#ifndef TUI_H
#define TUI_H

#include "pkt_monitor.h"

int  tui_init(const char *device, const char *direction);
void tui_update(const packet_counter_t *current,
                const packet_counter_t *total,
                int elapsed_sec, int paused);
void tui_cleanup(void);
int  tui_handle_input(void);  /* returns: 0=continue, 'q'=quit, 'p'=pause, 'r'=reset */

#endif /* TUI_H */
