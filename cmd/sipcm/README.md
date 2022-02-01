# sipcm

sipcm uses [sipcallmon](https://github.com/intuitivelabs/sipcallmon/) to
 implement functionality similar to
 [sipcmbeat](https://github.com/intuitivelabs/sipcmbeat/), but without
 sending the actual events anywhere (they can only be accessed through
 the local web interface).

sipcm keeps statistics and sip call state and can display them using
its built-in web interface.

It can either capture live packets or replay pcap files.

### Command line options


```
  -bpf string
    	berkley packet filter for capture
  -calls_max_entries uint
    	maximum tracked calls (0 for unlimited)
  -calls_max_mem uint
    	maximum memory for keeping call state (0 for unlimited)
  -calls_timeouts hash ( {state: timeout, ...})
    	timeouts for each callstate (e.g. {inv_established: 7200s,})
  -contact_ignore_port
    	ignore port number when comparing contacts (but not AORs)
  -debug_calltr uint
    	debugging flags for call tracking (default 1)
  -end_force_timeout string
    	force call state timeout to this value on exit/end (default "0s")
  -end_wait string
    	wait this interval before exiting (valid in no run_forever mode) (default "0s")
  -event_buffer_size int
    	how many events will be buffered (default 10240)
  -event_types_blst string
    	list of event types that should be blacklisted, comma or space separated
  -evr_conseq_report_max uint
    	report blacklisted events only if the number is a multiple of this value (use 0 to disable) (default 10000)
  -evr_conseq_report_min uint
    	report blacklisted events only if the number is a multiple of this value and 2^k and < evr_conseq_report_max (default 100)
  -evr_gc_interval string
    	event rate periodic GC interval (default "10s")
  -evr_gc_max_run_time string
    	maximum runtime for each periodic GC run (default "1s")
  -evr_gc_old_age string
    	event rate old age: non-blst. entries idle for more then this value will be GCed (default "5m0s")
  -evr_gc_target uint
    	event rate periodic GC target: GC will stop if the number of remaining entries is less then this value (default 10)
  -evr_intervals string
    	event rate intervals list, comma or space separated (default "1s,1m0s,1h0m0s")
  -evr_limits string
    	event rate max values list, comma or space separated (default "20,240,3600")
  -evr_max_entries uint
    	maximum tracked event rates (default 1048576)
  -http_addr string
    	listen address for the internal http server
  -http_port int
    	port for the internal http server, 0 == disable
  -iface string
    	interface to capture packets from
  -log_level int
    	log level (default 2)
  -log_opt uint
    	log format options (default 1)
  -max_blocked_timeout string
    	maximum blocked timeout (default "250ms")
  -parse_log_level int
    	log level for capturing and parsing (default 1)
  -parse_log_opt uint
    	log format options for parsing
  -pcap string
    	read packets from pcap files
  -pcap_loop uint
    	loop through pcap files multiple times
  -reg_exp_delta uint
    	extra REGISTER expiration delta for absorbing delayed re-REGISTERs (default 30)
  -regs_max_entries uint
    	maximum tracked register bindings (0 for unlimited)
  -regs_max_mem uint
    	maximum memory for register bindings (0 for unlimited)
  -replay
    	replay packets from pcap keeping recorded delays between packets
  -replay_max_delay string
    	maximum delay when replaying pcaps (default "0s")
  -replay_min_delay string
    	minimum delay when replaying pcaps (default "0s")
  -replay_scale float
    	scale factor for inter packet delay intervals
  -run_forever
    	keep web server running
  -stats_groups string  (e.g. ["calls,pcap",])
    	counter groups reported on exit, comma or space separated (default "all")
  -tcp_connection_timeout string
    	tcp connection timeout (default "1h0m0s")
  -tcp_gc_int string
    	tcp connections garbage collection interval (default "30s")
  -tcp_reorder_timeout string
    	tcp reorder timeout (default "1m0s")
  -verbose
    	turn on verbose mode
  -vxlan_ports string
    	vxlan ports list, comma or space separated
```


### HTTP URL Paths

| URL Path | Description |
| -------- | ----------- |
| /about ||
| /about/config ||
| /calls | call tracking hash table statistics |
| /calls/list | list 100 calls (add ?n=NNN to change the number) |
| /calls/list/query | list only calls matching a query (form) |
| /calls/timeout | call tracking per state timeouts |
| /counters | list statistics counters (params: group, counter, short, flags) |
| /debug/options | logging and debugging options |
| /debug/forcetimeout | force timeout for all the tracked calls (params: timeout=duration , default 100ms)|
| /events | list first 100 events (add ?n=NNN to change the number) |
| /events/blst | blacklist specific event types |
| /events/query | list events matching the query (form) |
| /evrateblst | event rate based blacklist hash table statistics |
| /evrateblst/list | list first 100 event rate tracking entries (params: n, s, ip, rate, ridx, val, re) |
| /evrateblst/list/query | list event rate tracking entries matching a query (form) |
| /evrateblst/rates | rates value for blacklisting and blacklist reporting |
| /evrateblst/forcegc | force GC for event rate tracking entries (params: n = target) |
| /evrateblst/gccfg1 | periodic GC config for event rates entries |
| /evrateblst/gccfg2 | memory pressure GC config and strategies for event rates entries |
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
./sipcm -pcap test.pcap  -http_port 8081 -bpf "port 5060" -run_forever -event_buffer_size 100000 >/tmp/sipcm.log
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


