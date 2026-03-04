/*
 * tui.c - ncurses TUI for pkt_monitor
 */

#ifdef HAS_NCURSES

#include <ncurses.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>
#include "tui.h"

#define MIN_WIDTH  60
#define MIN_HEIGHT 15
#define BAR_MAX    20

static const char *tui_direction;
static volatile sig_atomic_t needs_resize = 0;

static void sigwinch_handler(int sig)
{
    (void)sig;
    needs_resize = 1;
}

int tui_init(const monitor_config_t *cfg)
{
    tui_direction = cfg->direction == 0 ? "both" :
                    cfg->direction == 1 ? "in" : "out";

    initscr();
    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(1, COLOR_GREEN,   -1);  /* bar fill */
        init_pair(2, COLOR_CYAN,    -1);  /* header */
        init_pair(3, COLOR_YELLOW,  -1);  /* totals */
        init_pair(4, COLOR_WHITE,   -1);  /* normal */
        init_pair(5, COLOR_MAGENTA, -1);  /* kbps */
        init_pair(6, COLOR_RED,     -1);  /* alert */
    }
    raw();      /* raw mode: Ctrl+C comes as char 3 instead of SIGINT */
    noecho();
    curs_set(0);
    keypad(stdscr, TRUE);
    timeout(100);  /* non-blocking getch, 100ms */

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

static void draw_row(int y, const char *label, uint32_t pps, uint32_t total,
                     double kbps, double max_kbps, int bar_width)
{
    mvprintw(y, 2, "  %-6s  %7" PRIu32 "  %9" PRIu32 "  ", label, pps, total);
    draw_bar(y, 30, bar_width, max_kbps > 0 ? kbps / max_kbps : 0);
    attron(COLOR_PAIR(5));
    printw("  %7.1f kbps", kbps);
    attroff(COLOR_PAIR(5));
}

/*
 * Draw common header: name, direction, elapsed, filter, duration countdown.
 * Returns the next available row.
 */
static int draw_header(const char *title, int elapsed_sec, int paused,
                       const monitor_config_t *cfg)
{
    int row = 0;
    int h, m, s;

    h = elapsed_sec / 3600;
    m = (elapsed_sec % 3600) / 60;
    s = elapsed_sec % 60;

    attron(COLOR_PAIR(2) | A_BOLD);
    mvprintw(row, 1, " pkt_monitor");
    attroff(A_BOLD);
    printw("  %s  %s  %02d:%02d:%02d", title, tui_direction, h, m, s);
    if (!cfg->no_promisc)
        printw("  [promisc]");

    /* Duration remaining */
    if (cfg->duration > 0) {
        int rem = cfg->duration - elapsed_sec;
        int rh, rm2, rs;
        if (rem < 0) rem = 0;
        rh = rem / 3600;
        rm2 = (rem % 3600) / 60;
        rs = rem % 60;
        printw("  [-%02d:%02d:%02d]", rh, rm2, rs);
    }

    if (paused) {
        attron(A_BOLD);
        printw("  [PAUSED]");
        attroff(A_BOLD);
    }
    attroff(COLOR_PAIR(2));
    row++;

    /* Filter info */
    if (cfg->filter_expr) {
        attron(A_DIM);
        mvprintw(row, 2, "filter: %s", cfg->filter_expr);
        attroff(A_DIM);
    }
    row++;

    /* Separator */
    mvhline(row, 1, ACS_HLINE, COLS - 2);
    row += 2;

    return row;
}

/*
 * Draw alert if bandwidth exceeds threshold.
 * Returns the next available row.
 */
static int draw_alert(int row, double total_kbps, const monitor_config_t *cfg)
{
    if (cfg->alert_kbps > 0 && total_kbps > cfg->alert_kbps) {
        row += 1;
        attron(COLOR_PAIR(6) | A_BOLD);
        mvprintw(row, 2, " ALERT: %.1f kbps > %.1f kbps threshold ",
                 total_kbps, cfg->alert_kbps);
        attroff(COLOR_PAIR(6) | A_BOLD);
        row++;
    }
    return row;
}

/*
 * Draw a single-interface view with protocol breakdown and bars.
 */
static int draw_single_iface(iface_ctx_t *ctx, int start_row,
                              const monitor_config_t *cfg)
{
    int row = start_row;
    int bar_width;
    double total_kbps, max_kbps;
    double kbps_ip, kbps_ipv6, kbps_arp, kbps_icmp, kbps_tcp, kbps_udp;
    const packet_counter_t *cur = &ctx->pkt_cnt;
    const packet_counter_t *total = &ctx->total_cnt;

    bar_width = COLS - 50;
    if (bar_width < 5) bar_width = 5;
    if (bar_width > BAR_MAX) bar_width = BAR_MAX;

    total_kbps = (double)cur->bytes * 8.0 / 1024.0;

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

    /* Column headers */
    attron(A_BOLD);
    mvprintw(row, 2, "  %-6s  %7s  %9s  %-*s  %13s",
             "Proto", "pkt/s", "Total", bar_width, "Bandwidth", "kbps");
    attroff(A_BOLD);
    row++;

    /* Separator */
    mvhline(row, 2, ACS_HLINE, COLS - 4);
    row++;

    /* Protocol rows - L4 -> L3 -> L2 order */
    /* L4 */
    attron(A_DIM);
    mvprintw(row, 2, "-- L4 --");
    attroff(A_DIM);
    row++;
    draw_row(row++, "TCP",   cur->tcp,  total->tcp,  kbps_tcp,  max_kbps, bar_width);
    draw_row(row++, "UDP",   cur->udp,  total->udp,  kbps_udp,  max_kbps, bar_width);
    /* L3 */
    attron(A_DIM);
    mvprintw(row, 2, "-- L3 --");
    attroff(A_DIM);
    row++;
    draw_row(row++, "IPv4",  cur->ip,   total->ip,   kbps_ip,   max_kbps, bar_width);
    draw_row(row++, "IPv6",  cur->ipv6, total->ipv6, kbps_ipv6, max_kbps, bar_width);
    draw_row(row++, "ICMP",  cur->icmp, total->icmp, kbps_icmp, max_kbps, bar_width);
    /* L2 */
    attron(A_DIM);
    mvprintw(row, 2, "-- L2 --");
    attroff(A_DIM);
    row++;
    draw_row(row++, "ARP",   cur->arp,  total->arp,  kbps_arp,  max_kbps, bar_width);

    /* Separator */
    mvhline(row, 2, ACS_HLINE, COLS - 4);
    row++;

    /* Total row */
    attron(COLOR_PAIR(3) | A_BOLD);
    mvprintw(row, 2, "  %-6s  %7" PRIu32 "  %9" PRIu32, "ALL", cur->all, total->all);
    attroff(COLOR_PAIR(3) | A_BOLD);
    move(row, 30 + bar_width);
    attron(COLOR_PAIR(5) | A_BOLD);
    printw("  %7.1f kbps", total_kbps);
    attroff(COLOR_PAIR(5) | A_BOLD);
    row++;

    /* Alert */
    row = draw_alert(row, total_kbps, cfg);

    return row;
}

/*
 * Draw a compact multi-interface view: one row per interface.
 */
static int draw_multi_iface(iface_ctx_t *ifaces, int count,
                            int start_row, const monitor_config_t *cfg)
{
    int row = start_row;
    double total_agg_kbps = 0;
    int i;

    /* Column headers - L4 -> L3 -> L2 order */
    attron(A_BOLD);
    mvprintw(row, 2, "  %-10s %5s %5s %5s %5s %5s %4s %4s %9s",
             "Iface", "all", "TCP", "UDP", "IPv4", "IPv6", "ICMP", "ARP", "kbps");
    attroff(A_BOLD);
    row++;
    mvhline(row, 2, ACS_HLINE, COLS - 4);
    row++;

    /* Per-second rows */
    for (i = 0; i < count; i++) {
        const packet_counter_t *c = &ifaces[i].pkt_cnt;
        double kbps = (double)c->bytes * 8.0 / 1024.0;
        total_agg_kbps += kbps;

        attron(COLOR_PAIR(4));
        mvprintw(row, 2, "  %-10s %5" PRIu32 " %5" PRIu32 " %5" PRIu32
                 " %5" PRIu32 " %5" PRIu32 " %4" PRIu32 " %4" PRIu32,
                 ifaces[i].name, c->all, c->tcp, c->udp, c->ip, c->ipv6,
                 c->icmp, c->arp);
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
    mvprintw(row, 2, "  %-10s %5s %5s %5s %5s %5s %4s %4s %9s",
             "Total", "all", "TCP", "UDP", "IPv4", "IPv6", "ICMP", "ARP", "kbps");
    attroff(A_BOLD);
    row++;
    mvhline(row, 2, ACS_HLINE, COLS - 4);
    row++;

    for (i = 0; i < count; i++) {
        const packet_counter_t *t = &ifaces[i].total_cnt;
        double kbps = ifaces[i].elapsed_sec > 0
            ? (double)t->bytes * 8.0 / 1024.0 / ifaces[i].elapsed_sec : 0;

        attron(COLOR_PAIR(3));
        mvprintw(row, 2, "  %-10s %5" PRIu32 " %5" PRIu32 " %5" PRIu32
                 " %5" PRIu32 " %5" PRIu32 " %4" PRIu32 " %4" PRIu32,
                 ifaces[i].name, t->all, t->tcp, t->udp, t->ip, t->ipv6,
                 t->icmp, t->arp);
        attroff(COLOR_PAIR(3));
        attron(COLOR_PAIR(5));
        printw(" %8.1f", kbps);
        attroff(COLOR_PAIR(5));
        row++;
    }

    /* Alert */
    row = draw_alert(row, total_agg_kbps, cfg);

    return row;
}

void tui_update(iface_ctx_t *ifaces, int iface_count,
                int paused, const monitor_config_t *cfg)
{
    int row;
    char title[64];
    int elapsed;

    if (needs_resize) {
        needs_resize = 0;
        endwin();
        refresh();
    }

    erase();

    /* Build title string */
    elapsed = ifaces[0].elapsed_sec;
    if (iface_count == 1)
        snprintf(title, sizeof(title), "%s", ifaces[0].name);
    else
        snprintf(title, sizeof(title), "%d ifaces", iface_count);

    row = draw_header(title, elapsed, paused, cfg);

    if (iface_count == 1)
        draw_single_iface(&ifaces[0], row, cfg);
    else
        draw_multi_iface(ifaces, iface_count, row, cfg);

    /* Footer */
    row = LINES - 2;
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
    if (ch == 'q' || ch == 'Q' || ch == 3 /* Ctrl+C */)
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
