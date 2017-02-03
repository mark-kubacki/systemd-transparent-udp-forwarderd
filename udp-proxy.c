#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

#include <fcntl.h>

#include <systemd/sd-daemon.h>
#include <systemd/sd-journal.h>

#include "libmill.h"
#include "udp.c"

static int signal_pipe[2];

void signal_callback_handler(int posix_signal_number) {
	char as_byte = posix_signal_number;
	if (write(signal_pipe[1], &as_byte, 1) != 1) {
		sd_journal_print(LOG_DEBUG, "Did not write *one* byte to the signal pipe.");
	}
}

struct mill_udpsock_ *fd_to_udpsock(int udp_fd) {
	// Configures the socket as nonblocking.
	int opt = fcntl(udp_fd, F_GETFL, 0);
	if (opt == -1) {
		opt = 0;
	}
	int rc = fcntl(udp_fd, F_SETFL, opt | O_NONBLOCK);
	if (rc == -1) {
		sd_journal_print(LOG_ERR, "Cannot set the socket to nonblocking.");
		return NULL;
	}

	// Convert it to libmill's structs.
	struct mill_udpsock_ *us = malloc(sizeof(struct mill_udpsock_));
	memset(us, 0, sizeof(struct mill_udpsock_));
	if (!us) {
		sd_journal_print(LOG_CRIT, "Malloc failed for udpsock struct.");
		fdclean(udp_fd);
		close(udp_fd);
		errno = ENOMEM;
		return NULL;
	}
	us->fd = udp_fd;

	struct sockaddr_in addr;
	addr.sin_port = 0; // Zero, because we ignore any errors.
	socklen_t len = sizeof(struct sockaddr);
	getsockname(udp_fd, (struct sockaddr *) &addr, &len);
	us->port = ntohs(addr.sin_port);

	return us;
}

coroutine void udp_forward(udpsock us, char* destination) {
	// Do the receiving.
	char buf[9015]; // enough to hold a jumbo packet
	while(1) {
		ipaddr addr;
		size_t nbytes = udprecv(us, &addr, buf, sizeof(buf), -1);
		if (errno !=  0) {
			return;
		}
		sd_journal_print(LOG_DEBUG, "Got %lu bytes for %s.", nbytes, destination);
	}
}

int main(int argc, char *argv[]) {
	int n_systemd_sockets = sd_listen_fds(0);
	if ((n_systemd_sockets + 1) != argc) {
		sd_journal_print(LOG_ERR, "Mismatch in received sockets %d != %d destinations.", n_systemd_sockets, (argc - 1));
		return 1;
	}

	int err = pipe(signal_pipe);
	if (err != 0) {
		sd_journal_print(LOG_CRIT, "Cannot create the signals pipe.");
		return 72;
	}

	for (int i = 0; i < n_systemd_sockets; i++) {
		udpsock us = fd_to_udpsock(SD_LISTEN_FDS_START + i);
		go( udp_forward(us, argv[i]));
	}

	signal(SIGTERM, signal_callback_handler);
	signal(SIGKILL, signal_callback_handler);
	int exit_code = 0;
	while(1) {
		int events = fdwait(signal_pipe[0], FDW_IN, -1);
		if (events != FDW_IN) {
			continue;
		}

		char signal_as_byte;
		ssize_t sz = read(signal_pipe[0], &signal_as_byte, 1);
		if (sz != 1) {
			// Cannot happen, but just in case be verbose.
			sd_journal_print(LOG_ERR, "%lu != 1 bytes read from signal pipe.", sz);
			exit_code = 3;
			goto exit;
		}
		switch (signal_as_byte) {
		case SIGTERM:
		case SIGKILL:
			goto exit;
		}
	}

exit:
	sd_journal_print(LOG_INFO, "Closing sockets before exiting.");
	for (int i = 0; i < argc; ++i) {
		// fdclean(SD_LISTEN_FDS_START + i); -- No needed here.
		close(SD_LISTEN_FDS_START + i);
	}

	return exit_code;
}
