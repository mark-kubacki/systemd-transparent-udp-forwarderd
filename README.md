# Transparent socket-activated UDP Proxy/Forwarder for systemd

Written as quick workaround to
**systemd-socket-proxyd** as of systemd v231 not forwarding UDP datagrams.

Does not convert between IPv4 and IPv6.
The family of incoming and outgoing sockets/addresses must match.

## Requirements

 * systemd v221 or later (tested with v231)
 * Linux 3.10.0 or later
 * GCC to compile this

## Compile

The usual `gcc -Os -o systemd-transparent-udp-forwarderd *.c -lsystemd`,
or use **cmake**:

```bash
mkdir build && cd $_ && \
CFLAGS="-march=silvermont -mtune=intel" cmake -GNinja .. && \
ninja -v

# or, if you prefer make:
mkdir build && cd $_ && \
CFLAGS="-march=silvermont -mtune=intel" cmake .. && \
make
```

## Run

We will use **Avorion**, a random game, for this example.
It expects UDP packets on ports 27000, 27003, 27020, and 27021, but cannot be socket-activated.
It's *service file* looks like this (excerpt):

```ini
# avorion-server.service
[Service]
ExecStart=/usr/bin/rkt run \
  --dns=host --net="ptp0:IP=172.16.28.240" \
  blitznote.com/aci/avorion-server
```

We need to forward UDP datagrams arriving at the host to above container address.

Unlike *systemd-socket-proxyd* *systemd-transparent-udp-forwarderd* can handle more than one socket.
We can therefore write:

```ini
# proxy-to-avorion-udp.socket
[Socket]
ListenDatagram=0.0.0.0:27000
ListenDatagram=0.0.0.0:27003
ListenDatagram=0.0.0.0:27020
ListenDatagram=0.0.0.0:27021
Transparent=true

[Install]
WantedBy=sockets.target
```

… which, if enabled, on incoming datagrams starts:

```ini
# proxy-to-avorion-udp.service
[Unit]
BindsTo=avorion-server.service
After=avorion-server.service

[Service]
Type=notify
ExecStart=/opt/sbin/systemd-transparent-udp-forwarderd \
  172.16.28.240:27000 \
  172.16.28.240:27003 \
  172.16.28.240:27020 \
  172.16.28.240:27021
```

### Please Note

Packets sent to the container will not have the host's address, but will appear to have been sent by
a remote source (»originator«).

Responses will not go through this *forwarder*. Instead, whatever is in the container will address them to the originator(s)' IPs.

Remember to configure `SNAT`/`MASQUERADE` rules to modify the source address of outgoing packets.
If you forgot this, your server will emit IP packets with a container-local address as source,
which in turn will most likely result in them being suppressed by your DC/network operator.
*Kubernetes* and other orchestration tools do set them automatically, though.
