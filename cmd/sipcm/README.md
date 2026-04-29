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
    	event rate old age: non-blst. entries idle for more than this value will be GCed (default "5m0s")
  -evr_gc_target uint
    	event rate periodic GC target: GC will stop if the number of remaining entries is less than this value (default 10)
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
  -ipfix_addr string
    	listen address for the oracle/acme IPFIX message collector
  -ipfix_ignore_egress
    	ignore sip-egress IPFIX messages
  -ipfix_ignore_ingress
    	ignore sip-ingress IPFIX messages
  -ipfix_port int
    	port for receiving oracle/acme sbc IPFIX messages, 0 == disable
  -ipfix_rtp_quick_ev
    	generate a rtp_stats2 event immediately after receiving ipfix stats (default true)
  -ipfix_timeout_max int
    	maximum ipfix IO timeout, 0 == disable
  -ipfix_timeout_min int
    	minimum ipfix IO timeout, 0 == disable
  -log_level int
    	log level (default 2)
  -log_opt uint
    	log format options (default 1)
  -max_blocked_timeout string
    	maximum blocked timeout (default "250ms")
  -no_promiscuous_mode
    	do not put the interface into promiscuous mode (live capture only)
  -parse_log_level int
    	log level for capturing and parsing (default 1)
  -parse_log_opt uint
    	log format options for parsing
  -pcap string
    	read packets from pcap files
  -pcap_buf_kb int
    	libpcap capture buffer size in KiB
  -pcap_dump_on
    	enable/disable writing a pcap file for every call (pcap_dump_dir must also be set)
  -pcap_dump_dir string
    	write directory for the generated pcap per call files
  -pcap_dump_extension string
    	extension for the generated pcap per call files (default "pcap")
  -pcap_dump_fd_buckets int
    	number of hash buckets for the per-worker fd tracker (0 = disabled,
    	disables fd tracking and reverts to open/write/close per message)
  -pcap_dump_fd_max_open int
    	maximum globally tracked open pcap file descriptors (0 = unlimited)
  -pcap_dump_fd_prealloc int
    	number of pre-allocated fd tracker entries per worker (default 2048)
  -pcap_dump_file_upload_done_dir string
    	post-upload success action: "" = delete, "leave" = keep, or dir path to move to
  -pcap_dump_file_upload_err_dir string
    	post-upload error action: "" = leave, "delete" = remove, or dir path to move to
  -pcap_dump_file_upload_notify string
    	upload trigger mode: "channel" (default), "watch" (fsnotify), or "both"
  -pcap_dump_file_upload_queue int
    	upload channel and pool size for rotated pcap file uploads (default 1000)
  -pcap_dump_file_upload_workers int
    	number of upload worker goroutines for rotated pcap files (0 = disabled)
  -pcap_dump_flags int
    	pcap dump flags (future use)
  -pcap_dump_onerr
    	enable/disable appending error/bad messages to pcap per call files (pcap_dump_on must also be set)
  -pcap_dump_prefix string
    	prefix added to the name of the generated pcap per call files (default "callid_")
  -pcap_dump_queue_len int
    	message queue length for each of the pcap dump worker threads (default 10000)
  -pcap_dump_rotate_dir string
    	move rotated pcap files to this directory
  -pcap_dump_rotate_fmt string
    	format string for rotated filenames (default "" uses "%b_%s%e").
    	Specifiers: %b=base name, %e=extension, %f=full filename,
    	%s=unix seconds, %ms=milliseconds, %ns=nanoseconds,
    	%t{layout}=Go time format, %r=random hex, %i=upload id,
    	%n=monotonic counter, %R=conflict-only random, %N=conflict-only
    	counter, %U=conflict-only retry number, %%=literal %
  -pcap_dump_rotate_interval string
    	pcap file rotation interval (e.g. 10s) (default "10s")
  -pcap_dump_rotate_suffix string
    	rename rotated pcap files with this extension (e.g. .pcap)
  -pcap_dump_rtp
    	enable/disable appending RTP messages to pcap per call files (pcap_dump_on must also be set) (default true)
  -pcap_dump_subdirs int
    	number of subdirectories for spreading the pcap dump files
  -pcap_dump_suffix string
    	suffix added to the name of the generated pcap per call files
  -pcap_dump_upload string
    	upload URL for per-call pcap packets (using pcap uploader API)
  -pcap_dump_upload_id_hash string
    	method for generating the per call id for pcap dump upload (none, md5, sha256, xxhash, xxhash128, blake3_256, blake3_384) (default "none")
  -pcap_dump_upload_max_redir int
    	maximum number of redirects followed when uploading pcap packets (default 2)
  -pcap_dump_upload_rd_timeout string
    	pcap uploader network read timeout (default "10s")
  -pcap_dump_upload_wr_timeout string
    	pcap uploader network write timeout (default "5s")
  -pcap_dump_workers int
    	number of pcap dump worker threads (default 16)
  -pcap_loop uint
    	loop through pcap files multiple times
  -reg_del_delay int
    	RegDel event generation delay to work around quick reg.del re-reg
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
  -rtp
    	turn on rtp support (default true)
  -rtp_stats_interval int
    	rtp statistics event interval in seconds (0 for disabled)
  -run_forever
    	keep web server running
  -sdp
    	turn on sdp support
  -sdp_max_entry_mem uint
    	maximum memory for one SDP state entry (offer or answer) (default 65535)
  -sdp_total_mem uint
    	total memory reserved for keeping SDP state in Mb
  -sip_ports string
    	sip ports list, comma or space separated (if empty everything is treated as SIP)
  -stats_groups string  (e.g. ["calls,pcap",])
    	counter groups reported on exit, comma or space separated (default "all")
  -tcp_connection_timeout string
    	tcp connection timeout (default "1h0m0s")
  -tcp_gc_int string
    	tcp connections garbage collection interval (default "30s")
  -tcp_msg_buf int
    	initial size for the tcp reassembly message buffer (default 4096)
  -tcp_msg_buf_max int
    	maximum size for the tcp reassembly message buffer (default 16384)
  -tcp_reorder_timeout string
    	tcp reorder timeout (default "1m0s")
  -verbose
    	turn on verbose mode
  -vxlan_ports string
    	vxlan ports list, comma or space separated
  -websocket_ports string
    	websocket ports list, comma or space separated
```

The following options are read from the configuration file only (they
are not registered as command-line flags):

| Option | Description |
| ------ | ----------- |
| `cfg_ignore_unknown` | list of unknown config options to ignore |
| `encrypt_call_ids` | enable Call-ID anonymization |
| `encrypt_cbc_uri` | use AES CBC mode for URI encryption |
| `encrypt_ip_addresses` | enable IP address anonymization |
| `encrypt_ipcipher` | use ipcipher for IP address encryption |
| `encrypt_ua` | enable User-Agent string anonymization |
| `encrypt_uris` | enable URI anonymization |
| `encryption_key` | direct encryption key in hexadecimal format |
| `encryption_passphrase` | passphrase for key generation |
| `encryption_salt` | salt for encryption key validation |
| `geo_ip_db` | path to GeoIP database file |
| `geo_ip_on` | enable GeoIP lookup |
| `unencrypted_city_id` | keep city ID in plaintext (when using GeoIP) |
| `unencrypted_country_iso` | keep country ISO in plaintext (when using GeoIP) |

See `docs/Commandline.md` for the long-form description of every option.


### HTTP URL Paths

| URL Path | Description |
| -------- | ----------- |
| /about | server version, build tags and dependency info |
| /about/config | current configuration as command line args and parsed values |
| /calls | call tracking hash table statistics |
| /calls/list | list 100 calls (add ?n=NNN to change the number) |
| /calls/list/query | list only calls matching a query (form) |
| /calls/timeout | call tracking per state timeouts |
| /counters | list statistics counters (params: group, counter, short, nonzero, flags) |
| /counters/avg | print counters average (param: d=duration) |
| /debug/forcetimeout | force timeout for all the tracked calls (params: timeout=duration, default 100ms) |
| /debug/options | logging and debugging options |
| /debug/pprof | Go pprof profiling endpoints |
| /events | list first 100 events (add ?n=NNN to change the number) |
| /events/blst | blacklist specific event types |
| /events/query | list events matching the query (form) |
| /evrateblst | event rate based blacklist hash table statistics |
| /evrateblst/forcegc | force GC for event rate tracking entries (params: n = target) |
| /evrateblst/gccfg1 | periodic GC config for event rates entries |
| /evrateblst/gccfg2 | memory pressure GC config and strategies for event rates entries |
| /evrateblst/list | list first 100 event rate tracking entries (params: n, s, ip, rate, ridx, val, re) |
| /evrateblst/list/query | list event rate tracking entries matching a query (form) |
| /evrateblst/rates | rates value for blacklisting and blacklist reporting |
| /inject | inject a sip message (via web form) |
| /ipfix/list | list all the IPFIX probes connections (params: n, s) |
| /metrics | Prometheus metrics endpoint |
| /regs | registration bindings hash table statistics |
| /regs/cfg | registration configuration form |
| /regs/list | list 100 register bindings (add ?n=NNN to change) |
| /regs/list/query | list registration bindings matching query (form) |
| /rtp | RTP streams statistics |
| /rtp/list | list RTP streams |
| /rtp/list/query | query RTP streams (form) |
| /sdp/mem | SDP memory statistics |
| /stats | print received message statistics |
| /stats/avg | print message statistics average (param: d=duration, e.g. ?d=1m for last minute) |
| /stats/raw | print raw message statistics |
| /stats/rate | print message rates (time interval via ?d=.., default 1s) |
| /tcp/timeouts | TCP timeout configuration form |

See `docs/API.md` for the long-form description of every endpoint.

### Test using a pcap file

sipcm supports different pcap replay speeds:

 - normal recorded speed (simply add -replay to the command line options),
 - faster than recorded speed (add -replay and -replay\_scale N where N \< 1,
   e.g. -replay\_scale 0.1 for a 10x speed-up),
 - slower speed (-replay and -replay\_scale with a number greater than 1,
   e.g. -replay\_scale 2 for a 2x slow-down),
 - as fast as possible (no -replay in the command line, meaning replay all
   the packets immediately).

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
 running with -http_port 8081.
One just needs to paste the  message in the corresponding field and click
"Submit". The line termination format should be left to "auto detect" if the
message is long enough (\>8 lines).
