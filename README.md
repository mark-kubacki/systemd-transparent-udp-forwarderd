# Transparent socket-activated UDP Proxy/Forwarder for systemd

Written as quick workaround to
**systemd-socket-proxyd** not forwarding UDP datagrams.

* If you need more than one-way transparent forwarding, for example metrics, consider
  [Google’s Quilkin](https://github.com/googleforgames/quilkin).
* A nice tutorial for TCP (this project is for UDP) and socket-activation has
  [RedHat (serverless services)](https://www.redhat.com/en/blog/painless-services-implementing-serverless-rootless-podman-and-systemd)

## Caveats

 * Does not convert between IPv4 and IPv6.  
   The family of incoming and outgoing sockets/addresses must match.  
   (Just run this a second time to get both families covered.)
 * The maximum permissible payload size is hard-coded, and any
   larger than that gets silently discarded.

If you don't need the socket-activation you will be better served with
a DSTNAT/RNAT scheme and **nftables** (or `tc filter … nat`).

Other than that it's fine for all use-cases I've encountered.

## Requirements

 * systemd v221 or later (tested with v231)
 * Linux 3.10.0 or later
 * GCC to compile this

## Compile

The usual `gcc -D_GNU_SOURCE -Os -o systemd-transparent-udp-forwarderd *.c -lsystemd`,
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

We will use **Avorion** – a random game – in this example (find its *service unit* below),
which expects UDP packets on ports 27000, 27003, 27020, and 27021; but cannot be socket-activated.

Unlike *systemd-socket-proxyd*, *systemd-transparent-udp-forwarderd* can handle more than one socket:
(*Systemd* will listen on them to see when to proceed, but eventually relinquish control of those sockets to this *UDP proxy*.)

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

… which will start, by **systemd's** convention, following similarly named service on incoming datagrams.
That service in turn *binds to* another, and therefore makes *systemd* schedule its start as well.

```ini
# proxy-to-avorion-udp.service
[Unit]
BindsTo=avorion-server.service
After=avorion-server.service

# stop the game server if this service is stopped
PropagatesStopTo=avorion-server.service

[Service]
Type=notify
ExecStart=/opt/sbin/systemd-transparent-udp-forwarderd \
  172.16.28.240:27000 \
  172.16.28.240:27003 \
  172.16.28.240:27020 \
  172.16.28.240:27021 \
  1800
# ^^^^ this parameter is optional and allows the service to shut down after
#      1800 seconds of inactivity
```

Avorion's *service file* looks like this (excerpt). The corresponding *container address* is the important part:

```ini
# avorion-server.service
[Service]
ExecStart=/usr/bin/rkt run \
  --dns=host --net="ptp0:IP=172.16.28.240" \
  blitznote.com/aci/avorion-server
```

### Please Note

If you do not use any containers, i.e. the program runs on your host or with `--net=host`,
this section does not apply and you can skip reading it.

**Incoming packets** forwarded to the container will not appear to have been sent from the host.
They will retain their original source address;
and any response will be sent to them directly and not go through this *forwarder* by design.

Now, whatever is in the container will have an address specific to it, and needs to be changed to the host's.
Remember to configure `SNAT`/`MASQUERADE` rules to modify the source address of those **outgoing packets**.
(If you forgot this, your server will emit packets that won't have your host's as source,
which in turn will most likely result in them being suppressed by your DC/network operator
on account of appearing to have been forged or being non-routable.)
*Kubernetes* and other orchestration tools do set those rules automatically.

See for example `tc … action nat egress 172.16.28.240 <public host IPv4>`.
