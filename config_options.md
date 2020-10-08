
# Config options:

### Generic
* verbose - turn on verbose mode logging
* bpf     - berkley packet filter for capture
* pcap - pcap file for replay mode.
* iface - interface for real time packet capture

### pcap related

* replay - when replaying a pcap file, keep the delays between packets from the
         pcap
* replay_min_delay - force minimum inter-packet delay when replaying pcaps
* replay_max_delay - force maximum inter-packet delay when replaying pcaps
* replay_scale     - scale inter-packet delay by the given factor, when replaying
                   pcaps
* max_blocked_timeout - maximum blocked timeout when waiting for packets in
                      live capture mode (default is the tcp garbage collection
                      interval: tcp_gc_int, should be <= tcp_gc_int).



### http server

* http_port  - port for internal http server (0 means disable)
* http_addr  -  listen ip address for the internal http server
* run_forever  - keep web server running, even if in replay mode and the pcap
               file was fully replayed.

### TCP connection tracing
* tcp_gc_int - tcp garbage collection interval: tcp_reorder_timeout and
             and tcp_connection_timeout will be checked only every
             tcp_gc_int.
* tcp_reorder_timeout - tcp reorder timeout: tcp streams will stop waiting
                      for filling "re-order holes" for "holes" older than
                      this interval.
* tcp_connection_timeout - tcp stale connection timeout: tcp connections that
                         have not received any more data in this interval
                         will be "closed" (not tracked any longer).

### Events
* event_buffer_size - maximum number of events that will be buffered
                    (older events will be dropped if the events are not
                     read fast enough)

### call tracing
* reg_exp_delta  - extra REGISTER expiration delta for absorbing delayed
                 re-REGISTERs
* contact_ignore_port - ignore port number when comparing contacts (but not AORs)
