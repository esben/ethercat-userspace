/* EtherCAT master with no application task

   Copyright 2011-2015 Frank Heckenbach <f.heckenbach@fh-soft.de>

   This program is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation, either version 2 of
   the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program. If not, see <http://www.gnu.org/licenses/>. */

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include "globals.h"

volatile sig_atomic_t stop = 0;

static void handler(int sig)
{
    (void)sig;
    stop = 1;
}

void usage(FILE *f)
{
    fprintf(f, "Usage: ethercat_master [options] MASTER_MAC...\n"
               "Options:\n"
               "  -d VALUE  debug level\n"
               "  -b MAC    backup MAC\n");
}

int main(int argc, const char **argv)
{
    /* Command-line argument handling. */
    unsigned int debug_level = 0;
    unsigned int master_count = 0;
    unsigned int backup_count = 0;
    const char **masters = alloca(argc * sizeof(const char *));
    const char **backups = alloca(argc * sizeof(const char *));
    int i;
    for (i = 1; i < argc; i++) {
        const char *s = argv[i];
        if (strcmp(s, "--help") == 0) {
            usage(stdout);
            return EXIT_SUCCESS;
        } else if (strcmp(s, "--version") == 0) {
            printf("ethercat_master " EC_MASTER_VERSION "\n\n"
                   "EtherCAT master with no application task\n\n"
                   "This is free software; see the source for copying conditions.\n"
                   "There is NO warranty; not even for MERCHANTABILITY or\n"
                   "FITNESS FOR A PARTICULAR PURPOSE.\n\n"
                   "For more information about these matters, see the file named\n"
                   "COPYING.\n\n"
                   "Report bugs to " PACKAGE_BUGREPORT ".\n");
            return EXIT_SUCCESS;
        } else if (strcmp(s, "-d") == 0 && i + 1 < argc)
            debug_level = atoi(argv[++i]);
        else if (!strncmp(s, "-d", 2))
            debug_level = atoi(s + 2);
        else if (strcmp(s, "-b") == 0 && i + 1 < argc)
            backups[backup_count++] = argv[++i];
        else if (!strncmp(s, "-b", 2))
            backups[backup_count++] = s + 2;
        else if (s[0] != '-')
            masters[master_count++] = s;
        else {
            usage(stderr);
            return EXIT_FAILURE;
        }
    }

    /* Initialize. */
    int r = ecrt_init(master_count, masters, backup_count, backups, debug_level);
    if (r) {
        fprintf(stderr, "*** Cannot initialize EtherCAT: %s.\n", strerror(-r));
        return EXIT_FAILURE;
    }

    /* Verify each master was assigned a device. */
    int j;
    for (j = 0; j < master_count; j++) {
        if (!ecrt_open_master(j)) {
            fprintf(stderr, "*** Cannot open master %i.\n", j);
            ecrt_done();
            return EXIT_FAILURE;
        }
    }

    /* Run until interrupted (no application task here). */
    signal(SIGTERM, handler);
    signal(SIGINT,  handler);
    signal(SIGHUP,  handler);
    while (!stop)
        pause();
    ecrt_done();
    return EXIT_SUCCESS;
}
