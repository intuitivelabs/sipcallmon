// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipcallmon

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers" // recommended
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"

	"github.com/intuitivelabs/calltr"
	"github.com/intuitivelabs/sipsp"
)

const (
	TCPstartupReorderTimeout = time.Second      // initial reorder timeout
	TCPstartupGCInt          = time.Second      // timeout for tcp in startup mode
	TCPstartupInt            = 60 * time.Second // tcp in "learning quick timeout mode"
)

// EvRing is the global ring where all the events will be put.
var EventsRing EvRing

func processPCAP(fname string, cfg *Config) {
	if fname == "" {
		fmt.Fprintf(os.Stderr, "error: processPCAP: empty filename\n")
		return
	}
	var h *pcap.Handle
	var err error

	if h, err = pcap.OpenOffline(fname); err != nil {
		fmt.Fprintf(os.Stderr, "error: processPCAP: %s\n", err)
		return
	}
	defer h.Close()
	if err = h.SetBPFFilter(cfg.BPF); err != nil {
		fmt.Fprintf(os.Stderr, "error: processLive: bpf %q: %s\n",
			cfg.BPF, err)
		return
	}
	//packetSrc := gopacket.NewPacketSource(h, h.LinkType())
	//processPacketsSlow(packetSrc, cfg, true)
	processPackets(h, cfg, cfg.Replay)
}

func processLive(iface, bpf string, cfg *Config) {

	var h *pcap.Handle
	var err error
	// TODO: option for snap len
	// wait forever: pcap.BlockForever
	timeout := cfg.TCPGcInt
	if timeout > cfg.MaxBlockedTo && cfg.MaxBlockedTo > 0 {
		timeout = cfg.MaxBlockedTo
	}
	if timeout <= 0 {
		timeout = pcap.BlockForever
	}

	if h, err = pcap.OpenLive(iface, 65535, true, timeout); err != nil {
		fmt.Fprintf(os.Stderr,
			"error: processLive: failed opening %q: %s\n", iface, err)
		return
	}
	if err = h.SetBPFFilter(bpf); err != nil {
		fmt.Fprintf(os.Stderr, "error: processLive: bpf %q: %s\n", bpf, err)
		return
	}
	defer h.Close()
	processPackets(h, cfg, false)
}

func printPacket(w io.Writer, cfg *Config, n int, sip, dip *net.IP, sport, dport int, name string, l int) {
	if cfg.Verbose {
		fmt.Fprintf(w, "%d. %s:%d -> %s:%d %s	payload len: %d\n",
			n, sip, sport, dip, dport, name, l)
	}
}

func printTLPacket(w io.Writer, cfg *Config, n int, ipl gopacket.NetworkLayer,
	trl gopacket.TransportLayer) {
	if cfg.Verbose {
		fmt.Fprintf(w, "%d. %s:%s -> %s:%s %s	payload len: %d\n",
			n, ipl.NetworkFlow().Src(), trl.TransportFlow().Src(),
			ipl.NetworkFlow().Dst(), trl.TransportFlow().Dst(),
			trl.LayerType(), len(trl.LayerPayload()))
	}
}

// return true if buf content is for sure not a SIP packet
func nonSIP(buf []byte, sip *net.IP, sport int, dip *net.IP, dport int) bool {
	if len(buf) <= 12 ||
		(!(buf[0] >= 'A' && buf[0] <= 'Z') &&
			!(buf[0] >= 'a' && buf[0] <= 'z')) {
		return true
	}
	return false
}

func processPackets(h *pcap.Handle, cfg *Config, replay bool) {
	n := 0
	/* needed layers */
	// link layers
	var sll layers.LinuxSLL // e.g.: pcap files captured on any interface
	var lo layers.Loopback
	var eth layers.Ethernet
	var ethllc layers.LLC  // needed for 802.3 and pcap files
	var dot1q layers.Dot1Q // wlan
	// network layers
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var ip6ext layers.IPv6ExtensionSkipper // TODO: IPv6Fragment ?
	// transport layers
	var udp layers.UDP
	var tcp layers.TCP
	var sctp layers.SCTP
	var tls layers.TLS
	//var appl gopacket.Payload
	// space for decoded layers: eth|sll, ip4|ip6, ?ip6ext?, tcp|udp|sctp, tls
	// (will be truncated and appended by parser.DecodeLayers(...) )
	decodedLayers := make([]gopacket.LayerType, 0, 5)
	//decodedLayers := []gopacket.LayerType{}
	var layerType gopacket.LayerType
	// h.LinkType.LayerType() always return Unknown (BUG)
	// workaround: choose layerType by hand for handled layers
	switch h.LinkType() {
	case layers.LinkTypeEthernet:
		layerType = layers.LayerTypeEthernet
	case layers.LinkTypeLinuxSLL:
		layerType = layers.LayerTypeLinuxSLL
	case 12, 14:
		// LinkType 12 or 14 == RawIP
		// see https://github.com/the-tcpdump-group/libpcap/blob/170f717e6e818cdc4bcbbfd906b63088eaa88fa0/pcap/dlt.h
		// not supported yet by gopacket
		// workarround: treat it the same as raw, direct IPv4
		// (alhough it could contain direct IPv6 too)
		// proper fix: create new LayerType with decodeIPv4or6 decoder
		// see https://github.com/google/gopacket/blob/master/layers/layertypes.go
		// and https://github.com/google/gopacket/blob/master/layers/enums.go#L96
		fallthrough
	case layers.LinkTypeRaw:
		layerType = layers.LayerTypeIPv4
		fmt.Printf("Raw LinkType %s => layerType IPV4 %s (raw layer %q)\n",
			h.LinkType(), layerType, layers.LinkTypeRaw.LayerType())
	case layers.LinkTypeLoop:
		layerType = layers.LayerTypeLoopback
	case layers.LinkTypeIPv4:
		layerType = layers.LayerTypeIPv4
	case layers.LinkTypeIPv6:
		layerType = layers.LayerTypeIPv6
	default: // fallback
		layerType = h.LinkType().LayerType()
	}
	if cfg.Verbose {
		fmt.Printf("LinkType %s (%d)=> forced layerType %q (from %q)\n",
			h.LinkType(), h.LinkType(),
			layerType, h.LinkType().LayerType())
	}
	parser := gopacket.NewDecodingLayerParser(layerType,
		&lo, &eth, &ethllc, &dot1q,
		&sll,
		&ip4, &ip6, &ip6ext,
		&udp, &tcp, &sctp, &tls,
		//&appl,
	)
	parser.IgnoreUnsupported = true // no error on unsupported layers
	parser.IgnorePanic = true       // TODO: it might be faster to handle panics
	// setup tcp reassembly
	tcpStreamFactory := SIPStreamFactory{
		bufSize: 4096,
	}
	tcpStreamFactory.SIPStreamOptions =
		SIPStreamOptions{Verbose: cfg.Verbose, W: os.Stdout}
	tcpStreamPool := tcpassembly.NewStreamPool(tcpStreamFactory)
	tcpAssembler := tcpassembly.NewAssembler(tcpStreamPool)
	// TODO: config options
	tcpAssembler.MaxBufferedPagesTotal = 1024 * 25
	tcpAssembler.MaxBufferedPagesPerConnection = 256

	tcpGCInt := TCPstartupGCInt
	tcpGCRun := time.Now().Add(tcpGCInt)
	statsUpd := time.Now().Add(5 * time.Second)
	tcpStartupOver := time.Now().Add(TCPstartupInt)
	tcpReorderTo := TCPstartupReorderTimeout // initial
	var last time.Time
nextpkt:
	for !stopProcessing {
		now := time.Now()
		if cfg.TCPGcInt > 0 && now.After(tcpGCRun) {
			if now.After(tcpStartupOver) {
				tcpGCInt = cfg.TCPGcInt // revert to normal config option
				tcpReorderTo = cfg.TCPReorderTo
			}
			tcpGCRun = now.Add(tcpGCInt)
			flushed, closed := tcpAssembler.FlushWithOptions(
				tcpassembly.FlushOptions{
					T:        now.Add(-cfg.TCPConnTo),
					CloseAll: true,
				})
			stats.tcpExpReorder += uint64(flushed)
			stats.tcpStreamTo += uint64(closed)
			flushed, closed = tcpAssembler.FlushWithOptions(
				tcpassembly.FlushOptions{
					T:        now.Add(-tcpReorderTo),
					CloseAll: false,
				})
			stats.tcpExpReorder += uint64(flushed)
			stats.tcpStreamTo += uint64(closed)
		}
		if now.After(statsUpd) {
			statsUpd = now.Add(5 * time.Second)
			statsRecRate(now, &stats, statsRate[:])
		}
		buf, ci, err := h.ZeroCopyReadPacketData()
		if err != nil {
			switch err {
			case pcap.NextErrorNoMorePackets, io.EOF:
				break nextpkt // EOF
			case pcap.NextErrorTimeoutExpired:
				// garbage collection timeout (handled above)
				// do nothing, skip loop
				if buf == nil || len(buf) == 0 {
					continue nextpkt
				}
			case pcap.NextErrorNotActivated:
				fmt.Printf("BUG: capture: filter not activated %d: %s\n",
					n, err)
				break nextpkt
			default:
				fmt.Printf("Error: capture: packet %d: %s\n", n, err)
			}
			continue nextpkt
		}
		if replay {
			ts := ci.Timestamp
			if !last.IsZero() {
				wait := ts.Sub(last)
				DBG("replay: wait %s\n", wait)
				if cfg.ReplayScale > 0 {
					wait = time.Duration(uint64(float64(wait) * cfg.ReplayScale))
					DBG("replay: wait scaled to %s\n", wait)
				}
				if cfg.ReplayMinDelay > wait {
					wait = cfg.ReplayMinDelay
				}
				if cfg.ReplayMaxDelay != 0 && wait > cfg.ReplayMaxDelay {
					wait = cfg.ReplayMaxDelay
				}
				DBG("replay: final %s\n", wait)
				if wait > 0 {
					time.Sleep(wait)
				}
			}
			last = ts
		}
		n++
		stats.n++
		err = parser.DecodeLayers(buf, &decodedLayers)
		// if error and no layers decoded or
		//  error != UnsupportedLayerType class of errors
		if err != nil {
			if _, ok := err.(gopacket.UnsupportedLayerType); !ok || len(decodedLayers) == 0 {
				fmt.Printf("Error: decoding packet %d: %s\n", n, err)
				stats.decodeErrs++
			}
		}
		if cfg.Verbose {
			fmt.Printf("link type %s: layer type: %s: packet %d size %d- decoded layers %v\n", h.LinkType(), layerType, n, len(buf), decodedLayers)
		}
		var sport, dport int
		var sip, dip net.IP
		var ipl gopacket.NetworkLayer
		var tl gopacket.TransportLayer
	nextlayer:
		for _, layer := range decodedLayers {
			switch layer {
			case layers.LayerTypeIPv4:
				ipl = &ip4
				sip = ip4.SrcIP
				dip = ip4.DstIP
				stats.ip4++
				if ip4.FragOffset != 0 ||
					(ip4.Flags&layers.IPv4MoreFragments != 0) {
					stats.ip4frags++
					// TODO: ipv4 defrag
				}
			case layers.LayerTypeIPv6:
				ipl = &ip6
				sip = ip6.SrcIP
				dip = ip6.DstIP
				stats.ip6++
			case layers.LayerTypeIPv6Fragment:
				stats.ip6frags++
			case layers.LayerTypeUDP:
				tl = &udp
				sport = int(udp.SrcPort)
				dport = int(udp.DstPort)
				stats.udpN++
				if ipl == &ip4 {
					stats.udp4++
				} else if ipl == &ip6 {
					stats.udp6++
				} else {
					DBG("strange packet %d  udp but no network layer"+
						": %s \n", n, udp.TransportFlow())
					stats.decodeErrs++
					continue nextpkt
				}
				printTLPacket(os.Stdout, cfg, n, ipl, tl)
				/*
					if udp.SrcPort != 5060 && udp.DstPort != 5060 {
						if cfg.Verbose {
							fmt.Printf("ignoring...\n\n")
						}
						break nextlayer
					}
				*/
				/*? check if udp truncated: parser.Truncated ? */
				/*
					if parser.Truncated {
						fmt.Printf("udp packet %d truncated\n", n)
					}
				*/
				stats.seen++
				var payload []byte = tl.LayerPayload()
				if !nonSIP(payload, &sip, sport, &dip, dport) {
					udpSIPMsg(os.Stdout, payload, n, &sip, sport, &dip, dport,
						cfg.Verbose)
				}
				break nextlayer // exit the loop

			case layers.LayerTypeTCP:
				tl = &tcp
				sport = int(tcp.SrcPort)
				dport = int(tcp.DstPort)
				stats.tcpN++
				if ipl == &ip4 {
					stats.tcp4++
				} else if ipl == &ip6 {
					stats.tcp6++
				} else {
					DBG("strange packet %d  tcp but no network layer"+
						": %s \n", n, tcp.TransportFlow())
					stats.decodeErrs++
					continue nextpkt
				}
				printTLPacket(os.Stdout, cfg, n, ipl, tl)
				//DBG("DBG: %q\n", tcp.Payload)
				// tcp reassembly
				ts := ci.Timestamp
				if replay {
					ts = now
				}
				tcpAssembler.AssembleWithTimestamp(ipl.NetworkFlow(), &tcp, ts)
				break nextlayer
			case layers.LayerTypeSCTP:
				tl = &sctp
				sport = int(sctp.SrcPort)
				dport = int(sctp.DstPort)
				stats.sctpN++
				if ipl == &ip4 {
					stats.sctp4++
				} else if ipl == &ip6 {
					stats.sctp6++
				} else {
					DBG("strange packet %d  tcp but no network layer"+
						": %s \n", n, tcp.TransportFlow())
					stats.decodeErrs++
					continue nextpkt
				}
				printTLPacket(os.Stdout, cfg, n, ipl, tl)
				if cfg.Verbose {
					fmt.Printf("ignoring SCTP for now...\n\n")
				}
			case layers.LayerTypeTLS:
				if tl == &tcp {
					stats.tlsN++
				} else {
					stats.dtlsN++
				}
				if cfg.Verbose {
					fmt.Printf("ignoring TLS for now...\n\n")
				}
			}
		}
		if tl == nil {
			stats.otherN++
		}

	}
	// close all tcp connections, needed especially for file-mode, when
	// the pcap contains on-going tcp connections (w/o the initial SYNs).
	// Without this the tcpAssembler will wait for the missing data
	// and since processing a file is usually faster then the tcp timeout
	// interval, no tcp data for on-going connections will be processed in
	// the loop above, everything will be buffered...
	tcpAssembler.FlushAll()
}

func udpSIPMsg(w io.Writer, buf []byte, n int, sip *net.IP, sport int, dip *net.IP, dport int, verbose bool) bool {
	ret := true
	if verbose {
		fmt.Fprintf(w, "%q\n", buf)
	}
	var sipmsg sipsp.PSIPMsg
	sipmsg.Init(nil, nil, nil)
	o, err := sipsp.ParseSIPMsg(buf, 0, &sipmsg, sipsp.SIPMsgNoMoreDataF)
	if verbose {
		fmt.Fprintf(w, "after parsing => %d, %s\n", o, err)
	}
	if len(buf) > 12 || (len(buf) <= 12 && err != sipsp.ErrHdrTrunc) {
		if !verbose && (err != 0 || o != len(buf)) {
			fmt.Fprintf(w, "%d. %s:%d -> %s:%d UDP	payload len: %d\n",
				n, sip, sport, dip, dport,
				len(buf))
			fmt.Fprintf(w, "%q\n", buf)
		}
		if err != 0 {
			stats.errs++
			stats.errsUDP++
			stats.errType[err]++
			fmt.Fprintf(w, "unexpected error after parsing => %s\n", err)
			fmt.Fprintf(w, "parsed ok:\n%q\n", buf[:o])
			var l int
			if o < len(buf) {
				l = o + 40
				if l > len(buf) {
					l = len(buf)
				}
				fmt.Fprintf(w, "error before:\n%q\n", buf[o:l])
			}
			ret = false
		} else {
			stats.ok++
			stats.sipUDP++
			if sipmsg.FL.Request() {
				stats.reqsN++
				stats.method[sipmsg.FL.MethodNo]++
			} else {
				stats.replsN++
				stats.repl[sipmsg.FL.Status/100]++
			}
			var endPoints [2]calltr.NetInfo
			endPoints[0].SetIP(sip)
			endPoints[0].Port = uint16(sport)
			endPoints[0].SetProto(calltr.NProtoUDP)
			endPoints[1].SetIP(dip)
			endPoints[1].Port = uint16(dport)
			endPoints[1].SetProto(calltr.NProtoUDP)

			ret = CallTrack(&sipmsg, &endPoints)
			if ret {
				stats.callTrUDP++
			} else {
				stats.callTrErrUDP++
			}

		}
		if o != len(buf) {
			if err == 0 {
				stats.offsetErr++
			}
			fmt.Fprintf(w, "unexpected offset after parsing => %d / %d\n",
				o, len(buf))
			if err == 0 && int(sipmsg.Body.Len+sipmsg.Body.Offs) != len(buf) {
				stats.bodyErr++
				fmt.Fprintf(w, "clen: %d, actual body len %d, body end %d\n",
					sipmsg.PV.CLen.UIVal, int(sipmsg.Body.Len),
					int(sipmsg.Body.Len+sipmsg.Body.Offs))
				fmt.Fprintf(w, "body: %q\n", sipmsg.Body.Get(buf))
			}
		}
		if verbose || err != 0 || o != len(buf) {
			fmt.Fprintln(w)
		}
	} else {
		if len(buf) <= 12 {
			stats.tooSmall++
		}
		if verbose {
			fmt.Fprintln(w)
		}
		ret = false
	}
	return ret
}

var evCnt int64

// per event callback
func evHandler(ed *calltr.EventData) {
	atomic.AddInt64(&evCnt, 1)
	//fmt.Printf("Event %d: %s\n", evCnt, ed.String())
	if !EventsRing.Add(ed) {
		fmt.Fprintf(os.Stderr, "Failed to add event %d: %s\n",
			atomic.LoadInt64(&evCnt), ed.String())
	}
}

func CallTrack(m *sipsp.PSIPMsg, n *[2]calltr.NetInfo) bool {
	return calltr.Track(m, n, evHandler)
}
