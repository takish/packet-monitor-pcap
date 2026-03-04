/*
 * tui.c - ncurses TUI for pkt_monitor
 */

#ifdef HAS_NCURSES

#include <ncurses.h>
#include <string.h>
#include <signal.h>
#include "tui.h"

#define MIN_WIDTH  60
#define MIN_HEIGHT 15
#define BAR_MAX    20

static iface_ctx_t *tui_ifaces;
static int tui_iface_count;
static const char *tui_direction;
static volatile sig_atomic_t needs_resize = 0;

static void sigwinch_handler(int sig)
{
    (void)sig;
    needs_resize = 1;
}

int tui_init(iface_ctx_t *ifaces, int iface_count, const char *direction)
{
    initscr();
    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(1, COLOR_GREEN,   -1);  /* bar fill */
        init_pair(2, COLOR_CYAN,    -1);  /* header */
        init_pair(3, COLOR_YELLOW,  -1);  /* totals */
        init_pair(4, COLOR_WHITE,   -1);  /* normal */
        init_pair(5, COLOR_MAGENTA, -1);  /* kbps */
    }
    cbreak();
    noecho();
    curs_set(0);
    keypad(stdscr, TRUE);
    timeout(100);  /* non-blocking getch, 100ms */

    tui_ifaces = ifaces;
    tui_iface_count = iface_count;
    tui_direction = direction;

    signal(SIGWINCH, sigwinch_handler);

    if (COLS < MIN_WIDTH || LINES < MIN_HEIGHT) {
        endwin();
        fprintf(stderr, "Terminal too small (need %dx%d, have %dx%d)\n",
                MIN_WIDTH, MIN_HEIGHT, COLS, LINES);
        return -1;
    }

    return 0;
}

static void draw_bar(int y, int x, int width, double ratio)
{
    int filled, i;

    if (ratio > 1.0) ratio = 1.0;
    if (ratio < 0.0) ratio = 0.0;
    filled = (int)(ratio * width);

    move(y, x);
    attron(COLOR_PAIR(1));
    for (i = 0; i < filled; i++)
        addch(ACS_BLOCK);
    attroff(COLOR_PAIR(1));
    for (i = filled; i < width; i++)
        addch(ACS_BULLET);
}

static void draw_row(int y, const char *label, int pps, int total,
                     double kbps, double max_kbps, int bar_width)
{
    mvprintw(y, 2, "  %-6s  %7d  %9d  ", label, pps, total);
    draw_bar(y, 30, bar_width, max_kbps > 0 ? kbps / max_kbps : 0);
    attron(COLOR_PAIR(5));
    printw("  %7.1f kbps", kbps);
    attroff(COLOR_PAIR(5));
}

/*
 * Draw a single-interface view with protocol breakdown and bars.
 */
static int draw_single_iface(iface_ctx_t *ctx, int start_row, int paused)
{
    int row = start_row;
    int bar_width;
    double total_kbps, max_kbps;
    double kbps_ip, kbps_ipv6, kbps_arp, kbps_icmp, kbps_tcp, kbps_udp;
    const packet_counter_t *cur = &ctx->pkt_cnt;
    const packet_counter_t *total = &ctx->total_cnt;
    int h, m, s;

    bar_width = COLS - 50;
    if (bar_width < 5) bar_width = 5;
    if (bar_width > BAR_MAX) bar_width = BAR_MAX;

    total_kbps = (double)cur->bps * 8 / 1024;

    if (cur->all > 0) {
        kbps_ip   = total_kbps * cur->ip   / cur->all;
        kbps_ipv6 = total_kbps * cur->ipv6 / cur->all;
        kbps_arp  = total_kbps * cur->arp  / cur->all;
        kbps_icmp = total_kbps * cur->icmp / cur->all;
        kbps_tcp  = total_kbps * cur->tcp  / cur->all;
        kbps_udp  = total_kbps * cur->udp  / cur->all;
    } else {
        kbps_ip = kbps_ipv6 = kbps_arp = kbps_icmp = kbps_tcp = kbps_udp = 0;
    }

    max_kbps = total_kbps > 0 ? total_kbps : 1;

    /* Header */
    h = ctx->elapsed_sec / 3600;
    m = (ctx->elapsed_sec % 3600) / 60;
    s = ctx->elapsed_sec % 60;

    attron(COLOR_PAIR(2) | A_BOLD);
    mvprintw(row, 1, " pkt_monitor");
    attroff(A_BOLD);
    printw("  %s  %s  %02d:%02d:%02d", ctx->name, tui_direction, h, m, s);
    if (paused) {
        attron(A_BOLD);
        printw("  [PAUSED]");
        attroff(A_BOLD);
    }
    attroff(COLOR_PAIR(2));
    row++;

    /* Separator */
    mvhline(row, 1, ACS_HLINE, COLS - 2);
    row += 2;

    /* Column headers */
    attron(A_BOLD);
    mvprintw(row, 2, "  %-6s  %7s  %9s  %-*s  %13s",
             "Proto", "pkt/s", "Total", bar_width, "Bandwidth", "kbps");
    attroff(A_BOLD);
    row++;

    /* Separator */
    mvhline(row, 2, ACS_HLINE, COLS - 4);
    row++;

    /* Protocol rows */
    draw_row(row++, "IPv4",  cur->ip,   total->ip,   kbps_ip,   max_kbps, bar_width);
    draw_row(row++, "IPv6",  cur->ipv6, total->ipv6, kbps_ipv6, max_kbps, bar_width);
    draw_row(row++, "ARP",   cur->arp,  total->arp,  kbps_arp,  max_kbps, bar_width);
    draw_row(row++, "ICMP",  cur->icmp, total->icmp, kbps_icmp, max_kbps, bar_width);
    draw_row(row++, "TCP",   cur->tcp,  total->tcp,  kbps_tcp,  max_kbps, bar_width);
    draw_row(row++, "UDP",   cur->udp,  total->udp,  kbps_udp,  max_kbps, bar_width);

    /* Separator */
    mvhline(row, 2, ACS_HLINE, COLS - 4);
    row++;

    /* Total row */
    attron(COLOR_PAIR(3) | A_BOLD);
    mvprintw(row, 2, "  %-6s  %7d  %9d", "ALL", cur->all, total->all);
    attroff(COLOR_PAIR(3) | A_BOLD);
    move(row, 30 + bar_width);
    attron(COLOR_PAIR(5) | A_BOLD);
    printw("  %7.1f kbps", total_kbps);
    attroff(COLOR_PAIR(5) | A_BOLD);
    row++;

    return row;
}

/*
 * Draw a compact multi-interface view: one row per interface.
 */
static int draw_multi_iface(iface_ctx_t *ifaces, int count,
                            int start_row, int paused)
{
    int row = start_row;
    int h, m, s;

    /* Use first iface for elapsed time (all tick together) */
    h = ifaces[0].elapsed_sec / 3600;
    m = (ifaces[0].elapsed_sec % 3600) / 60;
    s = ifaces[0].elapsed_sec % 60;

    /* Header */
    attron(COLOR_PAIR(2) | A_BOLD);
    mvprintw(row, 1, " pkt_monitor");
    attroff(A_BOLD);
    printw("  %d ifaces  %s  %02d:%02d:%02d", count, tui_direction, h, m, s);
    if (paused) {
        attron(A_BOLD);
        printw("  [PAUSED]");
        attroff(A_BOLD);
    }
    attroff(COLOR_PAIR(2));
    row++;

    /* Separator */
    mvhline(row, 1, ACS_HLINE, COLS - 2);
    row += 2;

    /* Column headers */
    attron(A_BOLD);
    mvprintw(row, 2, "  %-10s %5s %5s %5s %4s %4s %5s %5s %9s",
             "Iface", "all", "IPv4", "IPv6", "ARP", "ICMP", "TCP", "UDP", "kbps");
    attroff(A_BOLD);
    row++;
    mvhline(row, 2, ACS_HLINE, COLS - 4);
    row++;

    /* Per-second rows */
    for (int i = 0; i < count; i++) {
        const packet_counter_t *c = &ifaces[i].pkt_cnt;
        double kbps = (double)c->bps * 8 / 1024;

        attron(COLOR_PAIR(4));
        mvprintw(row, 2, "  %-10s %5d %5d %5d %4d %4d %5d %5d",
                 ifaces[i].name, c->all, c->ip, c->ipv6,
                 c->arp, c->icmp, c->tcp, c->udp);
        attroff(COLOR_PAIR(4));
        attron(COLOR_PAIR(5));
        printw(" %8.1f", kbps);
        attroff(COLOR_PAIR(5));
        row++;
    }

    /* Separator + totals header */
    row++;
    mvhline(row, 2, ACS_HLINE, COLS - 4);
    row++;

    attron(A_BOLD);
    mvprintw(row, 2, "  %-10s %5s %5s %5s %4s %4s %5s %5s %9s",
             "Total", "all", "IPv4", "IPv6", "ARP", "ICMP", "TCP", "UDP", "kbps");
    attroff(A_BOLD);
    row++;
    mvhline(row, 2, ACS_HLINE, COLS - 4);
    row++;

    for (int i = 0; i < count; i++) {
        const packet_counter_t *t = &ifaces[i].total_cnt;
        double kbps = ifaces[i].elapsed_sec > 0
            ? (double)t->bps * 8 / 1024 / ifaces[i].elapsed_sec : 0;

        attron(COLOR_PAIR(3));
        mvprintw(row, 2, "  %-10s %5d %5d %5d %4d %4d %5d %5d",
                 ifaces[i].name, t->all, t->ip, t->ipv6,
                 t->arp, t->icmp, t->tcp, t->udp);
        attroff(COLOR_PAIR(3));
        attron(COLOR_PAIR(5));
        printw(" %8.1f", kbps);
        attroff(COLOR_PAIR(5));
        row++;
    }

    return row;
}

void tui_update(iface_ctx_t *ifaces, int iface_count, int paused)
{
    if (needs_resize) {
        needs_resize = 0;
        endwin();
        refresh();
    }

    erase();

    if (iface_count == 1)
        draw_single_iface(&ifaces[0], 0, paused);
    else
        draw_multi_iface(ifaces, iface_count, 0, paused);

    /* Footer */
    int row = LINES - 2;
    mvhline(row - 1, 1, ACS_HLINE, COLS - 2);
    attron(A_DIM);
    mvprintw(row, 2, "[q] Quit  [p] Pause  [r] Reset counters");
    attroff(A_DIM);

    refresh();
}

int tui_handle_input(void)
{
    int ch = getch();
    if (ch == ERR)
        return 0;
    if (ch == 'q' || ch == 'Q')
        return 'q';
    if (ch == 'p' || ch == 'P')
        return 'p';
    if (ch == 'r' || ch == 'R')
        return 'r';
    return 0;
}

void tui_cleanup(void)
{
    curs_set(1);
    endwin();
}

#endif /* HAS_NCURSES */
