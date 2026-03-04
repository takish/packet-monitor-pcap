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

static const char *tui_device;
static const char *tui_direction;
static volatile sig_atomic_t needs_resize = 0;

static void sigwinch_handler(int sig)
{
    (void)sig;
    needs_resize = 1;
}

int tui_init(const char *device, const char *direction)
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

    tui_device = device;
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

void tui_update(const packet_counter_t *cur,
                const packet_counter_t *total,
                int elapsed_sec, int paused)
{
    int row;
    int bar_width;
    double total_kbps;
    double max_kbps;
    double kbps_ip, kbps_ipv6, kbps_arp, kbps_icmp, kbps_tcp, kbps_udp;
    int h, m, s;

    if (needs_resize) {
        needs_resize = 0;
        endwin();
        refresh();
    }

    bar_width = COLS - 50;
    if (bar_width < 5) bar_width = 5;
    if (bar_width > BAR_MAX) bar_width = BAR_MAX;

    total_kbps = (double)cur->bps * 8 / 1024;

    /*
     * Estimate per-protocol bandwidth proportionally from packet counts.
     * True per-protocol byte tracking would require deeper packet inspection.
     */
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

    erase();

    /* Header */
    h = elapsed_sec / 3600;
    m = (elapsed_sec % 3600) / 60;
    s = elapsed_sec % 60;

    attron(COLOR_PAIR(2) | A_BOLD);
    mvprintw(0, 1, " pkt_monitor");
    attroff(A_BOLD);
    printw("  %s  %s  %02d:%02d:%02d", tui_device, tui_direction, h, m, s);
    if (paused) {
        attron(A_BOLD);
        printw("  [PAUSED]");
        attroff(A_BOLD);
    }
    attroff(COLOR_PAIR(2));

    /* Separator */
    mvhline(1, 1, ACS_HLINE, COLS - 2);

    /* Column headers */
    row = 3;
    attron(A_BOLD);
    mvprintw(row, 2, "  %-6s  %7s  %9s  %-*s  %13s",
             "Proto", "pkt/s", "Total", bar_width, "Bandwidth", "kbps");
    attroff(A_BOLD);

    /* Separator */
    row++;
    mvhline(row, 2, ACS_HLINE, COLS - 4);

    /* Protocol rows */
    row++;
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
    /* Skip bar for total */
    move(row, 30 + bar_width);
    attron(COLOR_PAIR(5) | A_BOLD);
    printw("  %7.1f kbps", total_kbps);
    attroff(COLOR_PAIR(5) | A_BOLD);

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
