#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>

#include <systemd/sd-daemon.h>
#include <systemd/sd-journal.h>
#include <systemd/sd-event.h>

#if !defined(likely)
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif

typedef union {
	struct sockaddr sa;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
} sockaddr_union;

#if !defined(WHITESPACE)
#define WHITESPACE      " \t\n\r"
#endif

/* Adapted from systemd. */
static int __attribute__((nonnull)) safe_atou16(const char *s, uint16_t *ret) {
	char *x = NULL;
	unsigned long l;

	s += strspn(s, WHITESPACE);

	errno = 0;
	l = strtoul(s, &x, 0);
	if (errno > 0)
		return -errno;
	if (!x || x == s || *x)
		return -EINVAL;
	if (s[0] == '-')
		return -ERANGE;
	if ((unsigned long) (uint16_t) l != l)
		return -ERANGE;

	*ret = (uint16_t) l;
	return 0;
}

/* These counters are reset in display_stats(). */
static size_t received_counter = 0, sent_counter = 0;

/* udp_forward sends the datagram from |*msg| to address |*dstaddr|.
 * Its source will be the original source found in |msg|.
 *
 * Address families of source and destination must match.
 *
 * This is called by |udp_receive|.
 *
 * Negative return values indicate an error. A corresponding error message
 * will be passed to systemd's journal. */
static int udp_forward(struct msghdr *msg, sockaddr_union *dstaddr) {
	auto in_family = ((struct sockaddr *)msg->msg_name)->sa_family;
	auto out_family = dstaddr->sa.sa_family;

	auto out = socket(out_family, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
	if (unlikely(out < 0)) {
		sd_journal_print(LOG_ERR, "Error creating outbound socket. (#%d %s)\n", errno, strerror(errno));
		return -2;
	}

	int n = 1;
	if (unlikely(setsockopt(out, SOL_IP, IP_TRANSPARENT, &n, sizeof(int)) != 0)) {
		sd_journal_print(LOG_ERR, "Error setting transparency towards destination. (#%d %s)\n", errno, strerror(errno));
		close(out);
		return -3;
	}

	/* IPv4 in IPv6 specialties */
	if (out_family == AF_INET6 && out_family != in_family) {
		int m = 0;
		if (setsockopt(out, IPPROTO_IPV6, IPV6_V6ONLY, &m, sizeof(int)) != 0) {
			sd_journal_print(LOG_ERR, "Error setting ipv6-only = no towards destination. (#%d %s)\n", errno, strerror(errno));
			close(out);
			return -6;
		}
	}

	/* spoof the sender */
	if (unlikely(bind(out, (struct sockaddr *)msg->msg_name, (in_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) < 0)) {
		sd_journal_print(LOG_ERR, "Error binding to destination. (#%d %s)\n", errno, strerror(errno));
		close(out);
		return -4;
	}

	ssize_t ret = sendto(out, msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len, 0,
		(struct sockaddr *)dstaddr, (out_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
	if (unlikely(ret <= 0)) {
		sd_journal_print(LOG_ERR, "Error sending to destination. (#%d %s)\n", errno, strerror(errno));
		close(out);
		return -5;
	}
	++sent_counter; /* Not thread-safe, but this is a single-threaded program. */

	close(out);
	return 0;
}

/* udp_receive() will refuse payloads greater than this.
 * 16k is greater than most common jumbo frames can accomdate (4098 to 9204 octets),
 * but smaller than multi-fragment datagrams (aout 65k) which are extremely uncommon in practice.
 * Please keep in mind that IPv6 allows you to stitch together packets to send a single big UDP payload (about 4G!). */
static const ssize_t max_accepted_payload_octets = 16 * 1024;

/* Used and to be cleared in udp_receive(), at least the size of max_accepted_payload_octets.
 * Allocated in main(). */
static void *payload_buffer;

/* udp_receive is called by the event loop and reads incoming datagrams from the supplied |fd|.
 * On success it will be handed over to |udp_forward| for forwarding.
 *
 * |*userdata| is expected to be a destination address.
 * A buffer to hold the payload of the incoming packet will be allocated by this callback.
 *
 * The event loop is responsible to call this.
 *
 * Negative return values indicate an fatal error. A corresponding error message will be sent to
 * systemd's journal. */
static int udp_receive(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
	++received_counter; /* Not thread-safe, but this is a single-threaded program. */

	ssize_t expected_octets = 0;
	if (unlikely(ioctl(fd, FIONREAD, &expected_octets) < 0)) { /* usually far less than 64k, more like 1.4k */
		return -errno;
	}
	if (unlikely(expected_octets > max_accepted_payload_octets)) {
		sd_journal_print(LOG_WARNING, "Dropped: Payload size exceeds maximum: %zd\n", expected_octets);
		/* We still need to call recvmsg, but with an empty buffer to get the message discarded. */
		expected_octets = 0;
	}

	struct msghdr msg;
	struct iovec iov[1];
	sockaddr_union sa;
	char cntrlbuf[64];

	memset(&msg, 0, sizeof(msg));
	memset(&sa, 0, sizeof(sa));
	memset(cntrlbuf, 0, sizeof(cntrlbuf));

	iov[0].iov_base = payload_buffer; /* MT */
	if (unlikely(expected_octets == 0)) {
		iov[0].iov_len = 0;
	} else {
		iov[0].iov_len = max_accepted_payload_octets; /* payload_buffer is at least that size */
	}
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_name = &sa.sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_control = cntrlbuf;
	msg.msg_controllen = sizeof(cntrlbuf);

	/* receive */
	ssize_t read_octets = recvmsg(fd, &msg, 0);
	if (unlikely(read_octets == 0)) { /* no payload, or we want to drop it anyway */
		return 0;
	}
	if (unlikely(read_octets < 0)) {
		if (likely(errno == EAGAIN)) {
			return 0;
		}
		sd_journal_print(LOG_WARNING, "Error calling recvmsg(). err (#%d %s)\n", errno, strerror(errno));
		return 0; /* 0 because this function can be called again for new packets */
	}
	if (unlikely(msg.msg_flags & (MSG_CTRUNC|MSG_TRUNC))) {
		sd_journal_print(LOG_WARNING, "Will forward a truncated datagram. Increase the recv buffers a bit to avoid this?\n");
	}
	msg.msg_iov[0].iov_len = read_octets; /* don't send the whole buffer */

	/* forward */
	sockaddr_union *dstaddr = userdata;
	udp_forward(&msg, dstaddr);

	return 0;
}

/* set_nonblocking sets a socket provided by |fd| to "non-blocking mode".
 * Calling this is only necessary once, at setup.
 *
 * Return values are from |fcntl|. */
static int set_nonblocking(int fd) {
	int opt = fcntl(fd, F_GETFL, 0);
	if (opt == -1) {
		opt = 0;
	}
	if ((opt | O_NONBLOCK) == opt) {
		return 0;
	}
	int rc = fcntl(fd, F_SETFL, opt | O_NONBLOCK);
	return rc;
}

/* hostnametoaddr translates a string |*hostname| to an address |*dstaddr|, preferably in
 * address family |preferred_sa_family| (IPv4, IPv6…).
 *
 * The provided |*dstaddr| must be empty, and already allocated.
 *
 * This really is an utility function for |fill_dstaddr|, which calls it.
 *
 * Negative return values indicate an error. */
static int hostnametoaddr(sockaddr_union *dstaddr, const char *hostname, int preferred_sa_family) {
	struct hostent *hostinfo = gethostbyname2(hostname, preferred_sa_family);
	if (hostinfo == NULL) {
		hostinfo = gethostbyname(hostname);
		if (hostinfo == NULL) {
			return -1;
		}
	}
	dstaddr->sa.sa_family = hostinfo->h_addrtype;

	if (hostinfo->h_addrtype == AF_INET6) {
		memcpy(&(dstaddr->in6.sin6_addr.s6_addr), hostinfo->h_addr,
			sizeof(dstaddr->in6.sin6_addr.s6_addr));
	} else {
		memcpy(&(dstaddr->in.sin_addr.s_addr), hostinfo->h_addr,
			sizeof(dstaddr->in.sin_addr.s_addr));
	}

	return 0;
}

/* fill_dstaddr is responsible for translating a user-provided destinations |*arg_remote_host|,
 * which can be an address or hostname, to an address |*dstaddr| we can forward datagrams to.
 * In case the user has forgotten to provide a destination port along with an address,
 * the destination port will be copied from |srcaddr| to |*dstaddr|.
 *
 * |*dstaddr| must be empty, and already allocated.
 *
 * This is used in |main| to initialize any and all |*dstaddr| in one place
 * to avoid costly address lookups.
 *
 * Negative return values indicate errors. */
static int fill_dstaddr(sockaddr_union *dstaddr, const sockaddr_union srcaddr, const char *arg_remote_host) {
	const char *node, *port_str;
	node = arg_remote_host;

	auto port = srcaddr.in.sin_port;
	if (srcaddr.sa.sa_family == AF_INET6) {
		port = srcaddr.in6.sin6_port;
	}
	port_str = strrchr(arg_remote_host, ':');
	if (port_str) { /* if a port is given: */
		node = strndupa(arg_remote_host, port_str - arg_remote_host);
		uint16_t portno = 0;
		if (safe_atou16(++port_str, &portno) < 0) {
			sd_journal_print(LOG_CRIT, "Failed to parse port number into 16b integer: %s", port_str);
			return -72;
		}
		port = htons(portno);
	}

	if (hostnametoaddr(dstaddr, node, srcaddr.sa.sa_family) < 0) {
		return -1;
	}

	if (dstaddr->sa.sa_family == AF_INET6) {
		dstaddr->in6.sin6_port = port;
	} else {
		dstaddr->in.sin_port = port;
	}

	return 0;
}

/* How often should we update PID 1 about our workload? */
static const uint64_t stats_every_usec = 10 * 1000000;

/* display_stats is a timer which updates PID 1 about the status of this process.
 * |sent_counter| and |received_counter| are read for that, and cleared afterwards.
 *
 * MT: This is not thread-safe, but this program is single-threaded.
 *
 * display_stats is expected to be called by the event loop. */
static int display_stats(sd_event_source *es, uint64_t now, void *userdata) {
	if (likely(sent_counter == received_counter)) { /* okay because this is a single-threaded program. */
		(void) sd_notifyf(false, "STATUS=%zu datagrams forwarded in the last %d seconds.",
			sent_counter, (unsigned int)(stats_every_usec / 1000000));
	} else if (sent_counter < received_counter) {
		(void) sd_notifyf(false, "STATUS=%zu datagrams forwarded in the last %d seconds, %zu not.",
			sent_counter, (unsigned int)(stats_every_usec / 1000000), received_counter - sent_counter);
	} else {
		(void) sd_notifyf(false, "STATUS=%zu datagrams forwarded in the last %d seconds, excess %zu.",
			sent_counter, (unsigned int)(stats_every_usec / 1000000), sent_counter - received_counter);
	}

	sent_counter = received_counter = 0;

	sd_event_source_set_time(es, now + stats_every_usec); /* reschedules */
	return 0;
}

/* main accepts any and all sockets handed over by PID 1, matches them with destinations from
 * |*argv[]|, and setups the event loop and its callbacks.
 *
 * The provided sockets will be closed on exit, which enables PID 1 to open new ones right away.
 *
 * Return values ≠0 indicate an error, and a corresponding error message will either be displayed
 * on STDERR, or sent to systemd's journal. */
int main(int argc, char *argv[]) {
	int n_systemd_sockets = sd_listen_fds(0);
	if ((n_systemd_sockets + 1) != argc) {
		sd_journal_print(LOG_ERR, "Mismatch in received sockets %d != %d destinations.", n_systemd_sockets, (argc - 1));
		return EXIT_FAILURE;
	}

	int exit_code = EXIT_SUCCESS;
	sd_event_source *event_source = NULL;
	sd_event_source *timer_source = NULL;
	sd_event *event = NULL;

	if (unlikely(sd_event_default(&event) < 0)) {
		sd_journal_print(LOG_DEBUG, "Cannot instantiate the event loop.");
		exit_code = 72;
		goto finish;
	}

	/* Register events without a callback, to trigger exit from the main event-loop call. */
	sigset_t ss;
	if (unlikely(sigemptyset(&ss) < 0 || sigaddset(&ss, SIGTERM) < 0 || sigaddset(&ss, SIGINT) < 0)) {
		exit_code = errno;
		goto finish;
	}
	if (unlikely(sigprocmask(SIG_BLOCK, &ss, NULL) < 0)) {
		exit_code = errno;
		goto finish;
	}
	if (unlikely(sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL) < 0 || sd_event_add_signal(event, NULL, SIGINT, NULL, NULL) < 0)) {
		exit_code = 73;
		goto finish;
	}

	/* Pull the watchdog, if requested. */
	if (sd_event_set_watchdog(event, true) < 0) {
		sd_journal_print(LOG_DEBUG, "Cannot pull the watchdog.");
		exit_code = 74;
		goto finish;
	}

	/* Setup the sockets. */
	for (int i = 0; i < n_systemd_sockets; i++) {
		auto fd = (SD_LISTEN_FDS_START + i);

		int r = sd_is_socket(fd, AF_UNSPEC, SOCK_DGRAM, -1);
		if (r < 0) {
			sd_journal_print(LOG_ERR, "Failed to determine socket type.");
			exit_code = 4;
			goto finish;
		} else if (r == 0) {
			sd_journal_print(LOG_ERR, "Passed in socket is not a datagram socket.");
			exit_code = 5;
			goto finish;
		}

		/* set to non-blocking */
		if (set_nonblocking(fd) < 0) {
			sd_journal_print(LOG_CRIT, "Cannot set the socket to nonblocking: %d", i);
			exit_code = 10;
			goto finish;
		}

		/* get the destination */
		sockaddr_union *dstaddr = alloca(sizeof(sockaddr_union));
		memset(dstaddr, 0, sizeof(sockaddr_union));

		sockaddr_union addr;
		memset(&addr, 0, sizeof(addr));
		socklen_t len = sizeof(addr);
		getsockname(fd, (struct sockaddr *) &addr, &len);

		if (fill_dstaddr(dstaddr, addr, argv[i+1]) < 0) {
			sd_journal_print(LOG_ERR, "Cannot get the destination for socket: %d", i);
			exit_code = 6;
			goto finish;
		}

		/* register */
		if (sd_event_add_io(event, &event_source, fd, EPOLLIN, udp_receive, dstaddr) < 0) {
			sd_journal_print(LOG_CRIT, "event_add_io failed for socket no: %d", i);
			exit_code = 72;
			goto finish;
		}
	}

	/* Allocate the payload buffer. */
	{
		size_t buffer_size = ((size_t)(max_accepted_payload_octets - 1)/4096 + 1) * 4096; /* multiple of 4k, the assumed page size */
		payload_buffer = malloc(buffer_size);
		if (unlikely(payload_buffer == NULL)) {
			exit_code = 71; /* save to assume it's a sys error if we don't have a few kb for malloc */
			goto finish;
		}
		memset(payload_buffer, 0, buffer_size);
	}

	/* Display some stats every now and then. */
	{
		uint64_t now;
		sd_event_now(event, CLOCK_MONOTONIC, &now);
		sd_event_add_time(event, &timer_source,
			CLOCK_MONOTONIC, now + stats_every_usec, 0,
			display_stats, NULL);
	}
	sd_event_source_set_enabled(timer_source, SD_EVENT_ON);

	/* Block on main event-loop call. */
	sd_journal_print(LOG_INFO, "Written by W. Mark Kubacki <wmark@hurrikane.de> https://github.com/wmark");
	sd_journal_print(LOG_INFO, "Done setting everything up. Serving.");
	(void) sd_notify(false, "READY=1\n" "STATUS=Up and running.");
	int r = sd_event_loop(event);
	if (r < 0) {
		sd_journal_print(LOG_ERR, "Failure: %s\n", strerror(-r));
		exit_code = -r;
	}

finish:
	if (timer_source != NULL) {
		sd_event_source_set_enabled(timer_source, SD_EVENT_OFF);
		timer_source = sd_event_source_unref(timer_source);
	}

	sd_journal_print(LOG_DEBUG, "Freeing reverences to event-source and the event-loop.");
	event_source = sd_event_source_unref(event_source);
	event = sd_event_unref(event);

	sd_journal_print(LOG_INFO, "Closing sockets before exiting.");
	for (int i = 0; i < argc; ++i) {
		/* fdclean(SD_LISTEN_FDS_START + i); -- Not needed here. */
		close(SD_LISTEN_FDS_START + i);
	}

	if (payload_buffer != NULL) {
		free(payload_buffer); /* makes static code analyzing tools happy */
	}

	return exit_code;
}
