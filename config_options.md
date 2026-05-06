# Config options

### Capture / Live Mode
* verbose - turn on verbose mode logging
* bpf - berkley packet filter for capture
* pcap - pcap file for replay mode.
* pcap_loop - loop through pcap files multiple times
* iface - interface to capture packets from
* pcap_buf_kb - size for pcap buffer in kb
* no_promiscuous_mode - do not put the interface into promiscuous mode
* max_blocked_timeout - maximum blocked timeout when waiting for packets in
  live capture mode (default "250ms")

### Logging
* log_level - log level (default 2, slog.LINFO)
* log_opt - log format options (default 1, slog.LlocInfoS)
* parse_log_level - log level for capturing and parsing (default 1, slog.LNOTICE)
* parse_log_opt - log format options for parsing (default 0, slog.LOptNone)
* debug_calltr - debugging flags for call tracking (default 1)

### PCAP Replay
* replay - when replaying a pcap file, keep the delays between packets from the
  pcap
* replay_min_delay - force minimum inter-packet delay when replaying pcaps (default "0s")
* replay_max_delay - force maximum inter-packet delay when replaying pcaps (default "0s")
* replay_scale - scale inter-packet delay by the given factor, when replaying
  pcaps (default 1.0)

### HTTP Server
* http_port - port for internal http server (0 means disable)
* http_addr - listen ip address for the internal http server

### TCP Connection Tracking
* tcp_gc_int - tcp garbage collection interval (default "30s")
* tcp_reorder_timeout - tcp reorder timeout (default "1m0s")
* tcp_connection_timeout - tcp stale connection timeout (default "1h0m0s")
* tcp_msg_buf - initial size for TCP reassembly message buffer (default 4096)
* tcp_msg_buf_max - maximum size for TCP reassembly message buffer (default 16384)

### SIP Ports
* sip_ports - list of ports to treat as SIP traffic, comma or space separated
  (if empty everything is treated as SIP)

### VXLAN
* vxlan_ports - list of UDP ports to treat as VXLAN traffic, comma or space separated

### WebSocket
* websocket_ports - list of TCP ports to treat as WebSocket traffic, comma or space separated

### IPFIX Collector
* ipfix_port - port for receiving Oracle/ACME SBC IPFIX messages (0 == disable)
* ipfix_addr - listen address for the Oracle/ACME IPFIX message collector
* ipfix_timeout_min - minimum IPFIX IO timeout in seconds (0 == disable)
* ipfix_timeout_max - maximum IPFIX IO timeout in seconds (0 == disable)
* ipfix_ignore_ingress - ignore SIP-ingress IPFIX messages
* ipfix_ignore_egress - ignore SIP-egress IPFIX messages
* ipfix_rtp_quick_ev - generate RTP stats event immediately after receiving IPFIX stats (default true)

### Call Tracking
* calls_max_entries - maximum tracked calls (0 for unlimited)
* calls_max_mem - maximum memory for keeping call state in bytes (0 for unlimited)
* calls_timeouts - timeouts for each call state, e.g. {inv_established:7200s,}
* reg_exp_delta - extra REGISTER expiration delta for absorbing delayed re-REGISTERs (default 30)
* reg_del_delay - RegDel event generation delay to work around quick reg-del re-reg (default 0)
* contact_ignore_port - ignore port number when comparing contacts (but not AORs)

### Registration Tracking
* regs_max_entries - maximum tracked register bindings (0 for unlimited)
* regs_max_mem - maximum memory for register bindings in bytes (0 for unlimited)

### Events
* event_buffer_size - maximum number of events that will be buffered (default 10240)
* event_types_blst - list of event types to blacklist, comma or space separated

### Event Rate Blacklist
* evr_max_entries - maximum tracked event rates (default 1048576)
* evr_limits - event rate max values list, comma or space separated (default "20,240,3600")
* evr_intervals - event rate intervals list, comma or space separated (default "1s,1m0s,1h0m0s")
* evr_conseq_report_min - report blacklisted events only if the number is a multiple of this
  value and 2^k and < evr_conseq_report_max (default 100)
* evr_conseq_report_max - report blacklisted events only if the number is a multiple of this
  value (default 10000, use 0 to disable)
* evr_gc_interval - event rate periodic GC interval (default "10s")
* evr_gc_old_age - event rate old age: non-blst entries idle for more than this value
  will be GCed (default "5m0s")
* evr_gc_max_run_time - maximum runtime for each periodic GC run (default "1s")
* evr_gc_target - event rate periodic GC target: GC will stop if the number of remaining
  entries is less than this value (default 10)

### PCAP Dump
* pcap_dump_on - enable/disable writing a pcap file for every call (pcap_dump_dir must also be set)
* pcap_dump_dir - write directory for generated pcap per call files
* pcap_dump_prefix - prefix added to the name of generated pcap per call files (default "callid_")
* pcap_dump_suffix - suffix added to the name of generated pcap per call files
* pcap_dump_extension - extension for the generated pcap per call files (default "pcap")
* pcap_dump_flags - pcap dump flags (future use)
* pcap_dump_onerr - enable/disable appending error/bad messages to pcap per call files
* pcap_dump_rtp - enable/disable appending RTP messages to pcap per call files (default true)
* pcap_dump_workers - number of pcap dump worker threads (default 16)
* pcap_dump_queue_len - message queue length for each pcap dump worker thread (default 10000)
* pcap_dump_subdirs - number of subdirectories for spreading the pcap dump files
* pcap_dump_fd_buckets - number of hash buckets for the per-worker fd tracker (0 = disabled)
* pcap_dump_fd_prealloc - number of pre-allocated fd tracker entries per worker (default 2048)
* pcap_dump_fd_max_open - maximum globally tracked open pcap file descriptors (0 = unlimited)
* pcap_dump_rotate_interval - pcap file rotation interval from first open (default "10s")
* pcap_dump_rotate_suffix - rename rotated pcap files with this extension (e.g. ".pcap")
* pcap_dump_rotate_dir - move rotated pcap files to this directory
* pcap_dump_rotate_fmt - format string for rotated filenames (default "" uses "%b_%s%e").
  Specifiers: %b=base name, %e=extension, %f=full filename,
  %s=unix seconds, %ms=milliseconds, %ns=nanoseconds,
  %t{layout}=Go time format, %r=random hex, %i=upload id,
  %n=monotonic counter, %R=conflict-only random, %N=conflict-only
  counter, %U=conflict-only retry number, %%=literal %

### PCAP Dump Upload
* pcap_dump_upload - upload URL for dumping pcap packets (using pcap uploader API)
* pcap_dump_upload_rd_timeout - pcap uploader network read timeout (default "10s")
* pcap_dump_upload_wr_timeout - pcap uploader network write timeout (default "5s")
* pcap_dump_upload_max_redir - maximum number of redirects followed when uploading (default 2)
* pcap_dump_upload_id_hash - method for generating per-call ID for upload
  (none, md5, sha256, xxhash, xxhash128, blake3_256, blake3_384)
* pcap_dump_upload_packet - stream each captured packet via the per-call upload API (default false; requires pcap_dump_upload; mutually exclusive with pcap_dump_upload_file)
* pcap_dump_upload_file - upload whole pcap files (default false; sets pcap_dump_file_upload_workers to 16 if 0; requires pcap_dump_upload; mutually exclusive with pcap_dump_upload_packet)

### PCAP File Upload (Rotated Files)
* pcap_dump_file_upload_workers - number of upload worker goroutines for rotated pcap files (0 = disabled)
* pcap_dump_file_upload_queue - upload channel and pool size for rotated pcap file uploads (default 1000)
* pcap_dump_file_upload_done_dir - post-upload success action: "" = delete, "leave" = keep, or dir path
* pcap_dump_file_upload_err_dir - post-upload error action: "" = leave, "delete" = remove, or dir path
* pcap_dump_file_upload_notify - upload trigger mode: "channel" (default), "watch" (fsnotify), or "both"
* pcap_dump_file_upload_startup_scan - on startup, scan pcap_dump_rotate_dir and upload any pre-existing files left over from a previous run (default true; requires pcap_dump_rotate_dir)

### RTP
* rtp - enable/disable RTP support (default true)
* rtp_stats_interval - RTP statistics event interval in seconds (0 for disabled)

### SDP
* sdp - turn on SDP support (required for RTP tracking)
* sdp_total_mem - total memory reserved for keeping SDP state in MB
* sdp_max_entry_mem - maximum memory for one SDP state entry (offer or answer)

### Anonymization / Encryption
* encrypt_ip_addresses - enable IP address anonymization
* encrypt_ipcipher - use ipcipher for IP address encryption
* encrypt_uris - enable URI anonymization
* encrypt_cbc_uri - use AES CBC mode for URI encryption
* encrypt_call_ids - enable Call-ID anonymization
* encrypt_ua - enable User-Agent string anonymization
* encryption_passphrase - passphrase for key generation
* encryption_key - direct encryption key in hexadecimal format
* encryption_salt - salt for encryption key validation
* unencrypted_country_iso - keep country ISO in plaintext (when using GeoIP)
* unencrypted_city_id - keep city ID in plaintext (when using GeoIP)

### GeoIP
* geo_ip_db - path to GeoIP database file
* geo_ip_on - enable GeoIP lookup

### Exit Options
* run_forever - keep web server running, even if in replay mode and the pcap
  file was fully replayed
* end_force_timeout - force call state timeout to this value on exit/end (default "0s")
* end_wait - wait this interval before exiting in no run_forever mode (default "0s")

### Statistics
* stats_groups - counter groups reported on exit, comma or space separated (default "all")
* stats_interval — periodic statistic events interval *(sipcmbeat only)* (default "5m0s")

### Configuration Management
* cfg_ignore_unknown - list of unknown config options to ignore (backward compatibility)
