/*
 * tui.h - ncurses TUI interface
 */

#ifndef TUI_H
#define TUI_H

#include "pkt_monitor.h"

int  tui_init(iface_ctx_t *ifaces, int iface_count, const char *direction);
void tui_update(iface_ctx_t *ifaces, int iface_count,
                int paused);
void tui_cleanup(void);
int  tui_handle_input(void);  /* returns: 0=continue, 'q'=quit, 'p'=pause, 'r'=reset */

#endif /* TUI_H */
