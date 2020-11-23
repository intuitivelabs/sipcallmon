# sipcm

sipcm keeps statistics and sip call state and can display them using
a built-in web interface.

It can either capture live packets or replay pcap files.

### Command line options


```
  -assembly_debug_log
    	If true, the github.com/google/gopacket/tcpassembly library will log verbose debugging information (at least one line per packet)
  -assembly_memuse_log
    	If true, the github.com/google/gopacket/tcpassembly library will log information regarding its memory use every once in a while.
  -bpf string
    	berkley packet filter for capture
  -contact_ignore_port
    	ignore port number when comparing contacts (but not AORs)
  -delay_scale float
    	scale factor for inter packet delay intervals
  -event_buffer_size int
    	how many events will be buffered (default 10240)
  -forever
    	keep web server running
  -i string
    	interface to capture packets from
  -l string
    	listen address for http server
  -max_blocked_timeout string
    	maximum blocked timeout (default "1s")
  -max_delay string
    	maximum delay when replaying pcaps (default "0s")
  -min_delay string
    	minimum delay when replaying pcaps (default "0s")
  -p int
    	port for http server, 0 == disable
  -pcap string
    	read packets from pcap files
  -reg_exp_delta uint
    	extra REGISTER expiration delta for absorbing delayed re-REGISTERs (default 30)
  -replay
    	replay packets from pcap keeping simulating delays between packets
  -tcp_connection_timeout string
    	tcp connection timeout (default "1h0m0s")
  -tcp_gc_interval string
    	tcp garbage collection interval (default "30s")
  -tcp_reorder_timeout string
    	tcp reorder timeout (default "1m0s")
  -verbose
    	turn on verbose mode
```


### HTTP URL Paths

| URL Path | Description |
| -------- | ----------- |
| /about ||
| /about/config ||
| /calls | call tracking hash table statistics |
| /calls/list | list 100 calls (add ?n=NNN to change the number) |
| /calls/list/query | list only calls matching a query (form) |
| /counters | list statistics counters |
| /events | list first 100 events (add ?n=NNN to change the number) |
| /events/blst | blacklist specific event types |
| /events/query | list events matching the query (form) |
| /inject | inject a sip message (via web form) |
| /regs | registration bindings hash table statistics |
| /regs/list | list 100 register bindings (add ?n=NNN to change) |
| /regs/list/query | list registration bindings matching query (form) |
| /stats | print received message statistics |
| /stats/avg | print message statistics average |
| /stats/avg?d=1m | print statistics average for the last minute (?d=1s last second, ?d=1h last hour ...) |
| /stats/raw | print raw message statistics |
| /stats/rate | print message rates (time interval via ?d=.., default 1s) |


### Test using a pcap file

sipcm supports different pcap replay speeds:

 - normal recorded speed (simply add -replay to the command line options),
 - faster then recorded speed (add -replay and -delay\_scale N where N \< 1,
 e.g. -delay\_scale 0.1 for a 10x speed-up)
 - slower speed ( -replay and  -delay\_scale with a number greater then 1,
 e.g. -delay\_scale 2 for a 2x slow-down)
 - as fast as possible (no -replay in the command line, meaning replay all
 the packets immediately)

Example pcap replay:

```
./sipcm -pcap test.pcap  -p 8081 -bpf "port 5060" -forever -event_buffer_size 100000 >/tmp/sipcm.log
```

Note that the event buffer should be large enough to save all the events you
might be interested in (-event\_buffer\_size NNNN)


### Injecting SIP packets using the web interface

SIP packets in pure ASCII format (e.g. pasted from RFC examples), ngrep
 txt dump format or with escaped CRLFs can be "injected" using the
 web interface /inject path, e.g. http://127.0.0.1:8081/inject if 
 running with -p 8081.
One just needs to paste the  message in the corresponding field and click
"Submit". The line termination format should be left to "auto detect" if the
message is long enouh (\>8 lines).


