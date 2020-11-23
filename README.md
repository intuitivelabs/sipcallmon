# sipcallmon

This go module provides the backbone for
[sipcmbeat](https://github.com/intuitivelabs/sipcmbeat/): configuration,
packet capture, sip message parsing and call tracking,
event generation, event ring (for caching events), statistics,
web interface a.s.o.

See [sipcmbeat README](https://github.com/intuitivelabs/sipcmbeat/blob/master/README.md)
for more details.

### sipcm

A stand alone binary that does everything that
[sipcmbeat](https://github.com/intuitivelabs/sipcmbeat/)
 does, but without sending any events to ES, can be found under
 [cmd/sipcm](./cmd/sipcm).
The generated events and statistics can be seen in the web interface.
It also supports replaying pcap files.

[sipcm](./cmd/sipcm) can be used for debugging or to see what
 [sipcmbeat](https://github.com/intuitivelabs/sipcmbeat/)
 would do, but without ES or configuring a local logstash output.


### Dependencies

sipcallmon depends on:

- [sipsp](https://github.com/intuitivelabs/sipsp)
- [calltr](https://github.com/intuitivelabs/calltr)
- [counters](https://github.com/intuitivelabs/counters)
- [bytescase](https://github.com/intuitivelabs/bytescase)
- [gopacket](https://github.com/google/gopacket)
