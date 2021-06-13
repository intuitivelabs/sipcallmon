// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipcallmon

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/bits"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers" // recommended
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"

	"github.com/intuitivelabs/calltr"
	"github.com/intuitivelabs/counters"
	"github.com/intuitivelabs/sipsp"
	"github.com/intuitivelabs/slog"
	"github.com/intuitivelabs/timestamp"
)

const (
	TCPstartupReorderTimeout = time.Second      // initial reorder timeout
	TCPstartupGCInt          = time.Second      // timeout for tcp in startup mode
	TCPstartupInt            = 60 * time.Second // tcp in "learning quick timeout mode"
)

// EvRing is the global ring where all the events will be put.
var EventsRing EvRing

// EvRateBlst is used to compute the generation rate for each event-ip pair
// and to mark/blacklist pairs that exceeded the configured maximum rates.
var EvRateBlst calltr.EvRateHash

// processPCAP  reads pcap packets from the given file and process them
// in the same way as they would have been if received from the wire.
// It returns the number of packet seen and the time it took to process
// the packets, the duration of the pcap file according to the pcap
// timestamps and an error (nil on success).
func processPCAP(fname string, cfg *Config) (uint64,
	time.Duration, time.Duration, error) {
	if fname == "" {
		ERR("processPCAP: empty filename\n")
		return 0, 0, 0, errors.New("processPcap: empty filename")
	}
	var h *pcap.Handle
	var err error

	if h, err = pcap.OpenOffline(fname); err != nil {
		ERR("processPCAP: %s\n", err)
		err = fmt.Errorf("processPCAP: open file %q: %w", fname, err)
		return 0, 0, 0, err
	}
	defer h.Close()
	if err = h.SetBPFFilter(cfg.BPF); err != nil {
		ERR("processLive: bpf %q: %s\n", cfg.BPF, err)
		err = fmt.Errorf("processPCAP: set bpf %q: %w", cfg.BPF, err)
		return 0, 0, 0, err
	}
	//packetSrc := gopacket.NewPacketSource(h, h.LinkType())
	//processPacketsSlow(packetSrc, cfg, true)
	return processPackets(h, cfg, cfg.Replay)
}

// processLive  received packets from the wire.
// It opens the given interface and applies the given berkley packet
// filter.
// Normally this function does not return on its own. It stops only if
// signaled that it should stop running or some error happens while
// trying to receive packets.
// It returns the number of packet seen, the total time it took to
// process the packets, the timestamp difference between the first
// and the last received packet, according to the packet receive timestamp
// and an error (nil on success).
func processLive(iface, bpf string, cfg *Config) (uint64,
	time.Duration, time.Duration, error) {

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
		ERR("processLive: failed opening %q: %s\n", iface, err)
		err = fmt.Errorf("processLive: failed to open %q: %w", iface, err)
		return 0, 0, 0, err
	}
	if err = h.SetBPFFilter(bpf); err != nil {
		ERR("processLive: bpf %q: %s\n", bpf, err)
		err = fmt.Errorf("processLive: bpf %q set failed: %w", bpf, err)
		return 0, 0, 0, err
	}
	defer h.Close()
	return processPackets(h, cfg, false)
}

func printPacket(w io.Writer, cfg *Config, n int, sip, dip net.IP, sport, dport int, name string, l int) {
	if cfg.Verbose && PDBGon() {
		PDBG("%d. %s:%d -> %s:%d %s	payload len: %d\n",
			n, sip, sport, dip, dport, name, l)
	}
}

func printTLPacket(w io.Writer, cfg *Config, n uint64,
	ipl gopacket.NetworkLayer, trl gopacket.TransportLayer) {
	if cfg.Verbose && PDBGon() {
		PDBG("%d. %s:%s -> %s:%s %s	payload len: %d\n",
			n, ipl.NetworkFlow().Src(), trl.TransportFlow().Src(),
			ipl.NetworkFlow().Dst(), trl.TransportFlow().Dst(),
			trl.LayerType(), len(trl.LayerPayload()))
	}
}

// return true if buf content is for sure not a SIP packet
func nonSIP(buf []byte, sip net.IP, sport int, dip net.IP, dport int) bool {
	if len(buf) <= 12 ||
		(!(buf[0] >= 'A' && buf[0] <= 'Z') &&
			!(buf[0] >= 'a' && buf[0] <= 'z')) {
		return true
	}
	return false
}

// process packets from a pcap handle using the provided config.
// If replay is true, it will delay processing a packet with the
// difference in pcap timestamps from the previous one.
// It returns the number of packets seen, the total time spent,
// the total time according to the pcap timestamps and an error.
func processPackets(h *pcap.Handle, cfg *Config, replay bool) (uint64,
	time.Duration, time.Duration, error) {
	var n uint64
	var err error
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
		PDBG("Raw LinkType %s => layerType IPV4 %s (raw layer %q)\n",
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
	if cfg.Verbose && PDBGon() {
		PDBG("LinkType %s (%d)=> forced layerType %q (from %q)\n",
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
		SIPStreamOptions{Verbose: cfg.Verbose, W: ioutil.Discard}
	tcpStreamPool := tcpassembly.NewStreamPool(tcpStreamFactory)
	tcpAssembler := tcpassembly.NewAssembler(tcpStreamPool)
	// TODO: config options
	tcpAssembler.MaxBufferedPagesTotal = 1024 * 25
	tcpAssembler.MaxBufferedPagesPerConnection = 256

	startTS := time.Now()
	tcpGCInt := TCPstartupGCInt
	tcpGCRun := time.Now().Add(tcpGCInt)
	statsUpd := time.Now().Add(5 * time.Second)
	tcpStartupOver := time.Now().Add(TCPstartupInt)
	tcpReorderTo := TCPstartupReorderTimeout // initial
	var startPCAPts time.Time
	var lastPCAPts time.Time
	var replayTS time.Time // sys time when a packet should be replied
	var sleep *time.Timer
nextpkt:
	for atomic.LoadUint32(&stopProcessing) == 0 {
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
			stats.Add(sCnts.tcpExpReorder, counters.Val(flushed))
			stats.Add(sCnts.tcpStreamTo, counters.Val(closed))
			flushed, closed = tcpAssembler.FlushWithOptions(
				tcpassembly.FlushOptions{
					T:        now.Add(-tcpReorderTo),
					CloseAll: false,
				})
			stats.Add(sCnts.tcpExpReorder, counters.Val(flushed))
			stats.Add(sCnts.tcpStreamTo, counters.Val(closed))
		}
		if now.After(statsUpd) {
			statsUpd = now.Add(5 * time.Second)
			statsRecRate(now, stats, statsRate[:])
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
				Plog.BUG("capture: filter not activated %d: %s\n", n, err)
				err = fmt.Errorf("processPackets: caputre BUG: %w", err)
				break nextpkt
			default:
				PERR("Error: capture: packet %d: %s\n", n, err)
			}
			continue nextpkt
		}
		if n == 0 {
			startPCAPts = ci.Timestamp
		}
		if replay {
			ts := ci.Timestamp
			if !lastPCAPts.IsZero() {
				wait := ts.Sub(lastPCAPts)
				//	PDBG("replay: wait %s\n", wait)
				if cfg.ReplayScale > 0 {
					wait = time.Duration(uint64(float64(wait) * cfg.ReplayScale))
					//	PDBG("replay: wait scaled to %s\n", wait)
				}
				if cfg.ReplayMinDelay > wait {
					wait = cfg.ReplayMinDelay
				}
				if cfg.ReplayMaxDelay != 0 && wait > cfg.ReplayMaxDelay {
					wait = cfg.ReplayMaxDelay
				}
				// PDBG("replay: final %s\n", wait)
				replayTS = replayTS.Add(wait)
				now := time.Now()
				if replayTS.Before(now) {
					wait = 0
					diff := now.Sub(replayTS)
					if diff > 10*time.Millisecond {
						// TODO: keep some counter for max diff and number of
						//       conseq big diffs.
						PDBG("replay wait too big, diff: %v\n", diff)
					}
				} else {
					wait = replayTS.Sub(now)
				}
				if wait > 0 {
					if sleep == nil {
						sleep = time.NewTimer(wait)
					} else {
						sleep.Reset(wait)
					}
					// equivalent to time.Sleep(wait), but handles stopCh
					select {
					case <-sleep.C:
					// do nothing (sleep period ended)
					case <-stopCh:
						// termination request via stopCh
						if !sleep.Stop() {
							// be nice and drain the channel
							<-sleep.C
						}
						break nextpkt
					}
				}
			} else {
				// initial, 0 ts => intialize replayTS
				replayTS = time.Now()
			}
		}
		lastPCAPts = ci.Timestamp // pcap timestamp of the last packet
		n++
		stats.Inc(sCnts.n)
		// size of packet on the wire
		stats.Add(sCnts.tsize, counters.Val(ci.Length))
		err = parser.DecodeLayers(buf, &decodedLayers)
		// if error and no layers decoded or
		//  error != UnsupportedLayerType class of errors
		if err != nil {
			if _, ok := err.(gopacket.UnsupportedLayerType); !ok || len(decodedLayers) == 0 {
				Plog.INFO("error decoding packet %d: %s\n", n, err)
				stats.Inc(sCnts.decodeErrs)
			}
		}
		if cfg.Verbose && PDBGon() {
			PDBG("link type %s: layer type: %s: packet %d size %d"+
				"- decoded layers %v\n",
				h.LinkType(), layerType, n, len(buf), decodedLayers)
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
				stats.Inc(sCnts.ip4)
				if ip4.FragOffset != 0 ||
					(ip4.Flags&layers.IPv4MoreFragments != 0) {
					stats.Inc(sCnts.ip4frags)
					// TODO: ipv4 defrag
				}
			case layers.LayerTypeIPv6:
				ipl = &ip6
				sip = ip6.SrcIP
				dip = ip6.DstIP
				stats.Inc(sCnts.ip6)
			case layers.LayerTypeIPv6Fragment:
				stats.Inc(sCnts.ip6frags)
			case layers.LayerTypeUDP:
				tl = &udp
				sport = int(udp.SrcPort)
				dport = int(udp.DstPort)
				stats.Inc(sCnts.udpN)
				if ipl == &ip4 {
					stats.Inc(sCnts.udp4)
				} else if ipl == &ip6 {
					stats.Inc(sCnts.udp6)
				} else {
					if PDBGon() {
						PDBG("strange packet %d  udp but no network layer"+
							": %s \n", n, udp.TransportFlow())
					}
					stats.Inc(sCnts.decodeErrs)
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
				stats.Inc(sCnts.seen)
				var payload []byte = tl.LayerPayload()
				if !nonSIP(payload, sip, sport, dip, dport) {
					udpSIPMsg(ioutil.Discard, payload, n, sip, sport,
						dip, dport, cfg.Verbose)
				} else {
					// not sip -> probe
					pktErrEvHandler(calltr.EvNonSIPprobe,
						sip, sport, dip, dport, calltr.NProtoUDP,
						nil, nil)
				}
				break nextlayer // exit the loop

			case layers.LayerTypeTCP:
				tl = &tcp
				sport = int(tcp.SrcPort)
				dport = int(tcp.DstPort)
				stats.Inc(sCnts.tcpN)
				if ipl == &ip4 {
					stats.Inc(sCnts.tcp4)
				} else if ipl == &ip6 {
					stats.Inc(sCnts.tcp6)
				} else {
					if PDBGon() {
						PDBG("strange packet %d  tcp but no network layer"+
							": %s \n", n, tcp.TransportFlow())
					}
					stats.Inc(sCnts.decodeErrs)
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
				stats.Inc(sCnts.sctpN)
				if ipl == &ip4 {
					stats.Inc(sCnts.sctp4)
				} else if ipl == &ip6 {
					stats.Inc(sCnts.sctp6)
				} else {
					if PDBGon() {
						PDBG("strange packet %d  tcp but no network layer"+
							": %s \n", n, tcp.TransportFlow())
					}
					stats.Inc(sCnts.decodeErrs)
					continue nextpkt
				}
				printTLPacket(os.Stdout, cfg, n, ipl, tl)
				if cfg.Verbose && PDBGon() {
					PDBG("ignoring SCTP for now...\n\n")
				}
			case layers.LayerTypeTLS:
				if tl == &tcp {
					stats.Inc(sCnts.tlsN)
				} else {
					stats.Inc(sCnts.dtlsN)
				}
				if cfg.Verbose && PDBGon() {
					PDBG("ignoring TLS for now...\n\n")
				}
			}
		}
		if tl == nil {
			stats.Inc(sCnts.otherN)
		}

	}
	endTS := time.Now()
	// close all tcp connections, needed especially for file-mode, when
	// the pcap contains on-going tcp connections (w/o the initial SYNs).
	// Without this the tcpAssembler will wait for the missing data
	// and since processing a file is usually faster then the tcp timeout
	// interval, no tcp data for on-going connections will be processed in
	// the loop above, everything will be buffered...
	tcpAssembler.FlushAll()
	return n, endTS.Sub(startTS), lastPCAPts.Sub(startPCAPts), err
}

// parse & process (calltrack) an udp message
// If verbose is set, extra information will be logged to w (otherwise only
// to the log)
func udpSIPMsg(w io.Writer, buf []byte, n uint64, sip net.IP, sport int,
	dip net.IP, dport int, verbose bool) bool {
	ret := true
	if verbose && (Plog.DBGon() || w != ioutil.Discard) {
		Plog.LogMux(w, verbose, slog.LDBG, "udp pkt: %q\n", buf)
	}
	var sipmsg sipsp.PSIPMsg
	sipmsg.Init(nil, nil, nil)
	o, err := sipsp.ParseSIPMsg(buf, 0, &sipmsg, sipsp.SIPMsgNoMoreDataF)
	if len(buf) > 12 || (len(buf) <= 12 && err != sipsp.ErrHdrTrunc) {
		if !verbose && (err != 0 || o != len(buf)) &&
			(Plog.L(slog.LNOTICE) || w != ioutil.Discard) {
			Plog.LogMux(w, true, slog.LNOTICE,
				"%d. %s:%d -> %s:%d UDP	payload len: %d\n",
				n, sip, sport, dip, dport,
				len(buf))
			Plog.LogMux(w, true, slog.LNOTICE, "%q\n", buf)
		}
		if err != 0 {
			stats.Inc(sCnts.errs)
			stats.Inc(sCnts.errsUDP)
			stats.Inc(sCnts.errType[err])
			if Plog.L(slog.LNOTICE) || w != ioutil.Discard {
				Plog.LogMux(w, true, slog.LNOTICE,
					"unexpected error after parsing => %s\n", err)
				Plog.LogMux(w, true, slog.LNOTICE, "parsed ok:\n%q\n", buf[:o])
			}
			var l int
			if o < len(buf) {
				l = o + 40
				if l > len(buf) {
					l = len(buf)
				}
				if Plog.L(slog.LNOTICE) || w != ioutil.Discard {
					Plog.LogMux(w, true, slog.LNOTICE, "error before:\n%q\n",
						buf[o:l])
				}
			}
			// parse error event
			rep := o
			// report for 60 parsed ok chars from the message
			if rep > 60 {
				rep = 60
			}
			pktErrEvHandler(calltr.EvParseErr,
				sip, sport, dip, dport, calltr.NProtoUDP,
				sipmsg.PV.GetCallID().CallID.Get(buf),
				buf[:rep])
			ret = false
		} else {
			stats.Inc(sCnts.ok)
			stats.Inc(sCnts.sipUDP)
			if sipmsg.FL.Request() {
				stats.Inc(sCnts.reqsN)
				stats.Inc(sCnts.method[sipmsg.FL.MethodNo])
			} else {
				stats.Inc(sCnts.replsN)
				if sipmsg.FL.Status < 1000 {
					stats.Inc(sCnts.repl[sipmsg.FL.Status/100])
				}
			}
			var endPoints [2]calltr.NetInfo
			endPoints[0].SetIP(sip)
			endPoints[0].Port = uint16(sport)
			endPoints[0].SetProto(calltr.NProtoUDP)
			endPoints[1].SetIP(dip)
			endPoints[1].Port = uint16(dport)
			endPoints[1].SetProto(calltr.NProtoUDP)

			ret = CallTrack(&sipmsg, endPoints)
			if ret {
				stats.Inc(sCnts.callTrUDP)
			} else {
				stats.Inc(sCnts.callTrErrUDP)
			}

		}
		if o != len(buf) {
			if err == 0 {
				stats.Inc(sCnts.offsetErr)
			}
			if Plog.L(slog.LNOTICE) || w != ioutil.Discard {
				Plog.LogMux(w, true, slog.LNOTICE,
					"unexpected offset after parsing => %d / %d\n",
					o, len(buf))
			}
			if err == 0 && int(sipmsg.Body.Len+sipmsg.Body.Offs) != len(buf) {
				stats.Inc(sCnts.bodyErr)
				if Plog.L(slog.LNOTICE) || w != ioutil.Discard {
					Plog.LogMux(w, true, slog.LNOTICE,
						"clen: %d, actual body len %d, body end %d\n",
						sipmsg.PV.CLen.UIVal, int(sipmsg.Body.Len),
						int(sipmsg.Body.Len+sipmsg.Body.Offs))
					Plog.LogMux(w, true, slog.LDBG, "body: %q\n",
						sipmsg.Body.Get(buf))
				}
			}
			// TODO: event for bad body over UDP?
		}
		if verbose || err != 0 || o != len(buf) {
			fmt.Fprintln(w)
		}
	} else {
		if len(buf) <= 12 {
			stats.Inc(sCnts.tooSmall)
		}
		if verbose {
			fmt.Fprintln(w)
		}
		ret = false
	}
	return ret
}

// Check if a blst event repeated count times should be reported or
// ignored, using minr (min repeat count report) and  maxr (max ...).
// A fresh new blst ev should have count == 1.
// Note: it should be called with count >= 1. Behaviour is undefined
//       for count == 0 (for now it returns true, but it might change
//       since count == 0 means not blacklisted)
// A blacklist event should be reported if:
//  - repeat count is 1 (this is the first blacklisted event)
//  - repeat count is a multiple of maxr
//  - repeat count is less then maxr and a multiple of minr * 2^k
//   (exponential backoff starting at minr and limited at maxr).
// Returns true if an event should be reported, false otherwise and the
//  computed difference from last count for each the function would have
//  returned true (usefull for adding  "N ignored since last time").
// Note: the difference is valid only if minr & maxr _did_ not change
//       between the calls.
func reportBlstEv(count uint64, minr uint64, maxr uint64) (bool, uint64) {
	// diff from previous  report, assuming minr & maxr did not change
	var diff uint64
	if count == 1 {
		return true, diff
	}
	if maxr != 0 && count >= maxr {
		if (count % maxr) == 0 {
			// if >= maxr, only report every maxr events
			if count == maxr {
				if minr == 0 || minr >= maxr {
					// minr never used
					diff = count - 1
				} else {
					// diff = count - max(2^k*minr) for k
					//     such that 2^k*minr < maxr
					t := (count - 1) / minr
					l := bits.Len64(t) // length in bits => k = l - 1
					// l cannot be 0 since  here minr < is at most count -1
					// (minr < maxr == count)
					diff = count - (1<<(l-1))*minr
				}
			} else {
				diff = maxr
			}
			return true, diff
		}
		return false, diff // not multiple of maxr
	}
	// report only if  it's a 2^k multiple of minr
	if (minr != 0) && (count%minr) == 0 {
		// here is a multiple of minr => check if multiple of 2^k
		t := count / minr
		if (t & (t - 1)) == 0 {
			if t == 1 {
				// if count == minr, diff from last report is
				// count - 1 (1st blst is always reported)
				diff = count - 1
			} else {
				// else diff = count - count_old =
				//             minr * 2^k - minr * 2^(k-1) =
				//             minr * 2^(k-1) = count/2
				diff = count / 2
			}
			//  multiple of 2^k =>  report
			return true, diff
		}
	}
	// if minr == 0 -> don't report anything till maxr
	// if maxr == 0 ->  keep reporting on 2^k multiple of minr
	// if minr == 0 && maxr == 0 -> don't report anything, except the 1st
	return false, diff
}

// per event callback
// NOTE: this handler is obsolete, see callEvHandler for the prefered version
func evHandler(ed *calltr.EventData) {
	var src calltr.NetInfo
	var diff uint64

	src.SetIP(ed.Src)
	src.SetProto(ed.ProtoF)

	evrStats.Inc(evrCnts.no)
	// check type blacklist from EvRing
	if EventsRing.Blacklisted(ed.Type) {
		evrStats.Inc(evrCnts.blstType)
		return
	}
	ok, ridx, rv, info :=
		EvRateBlst.IncUpdate(ed.Type, src, timestamp.Now())
	if !ok {
		evrStats.Inc(evrCnts.trackFail)
		if DBGon() {
			DBG("max event blacklist size exceeded: %v / %v\n",
				EvRateBlst.CrtEntries(), EvRateBlst.MaxEntries())
		}
		return
	}
	_, rateMax := EvRateBlst.GetRateMax(ridx)
	if info.Exceeded {
		evrStats.Inc(evrCnts.blstRate)
		if DBGon() {
			DBG("event %s src %s blacklisted: rate %f/%f per %v,"+
				" since %v (%v times)\n",
				ed.Type, src.IP(), rv, rateMax.Max, rateMax.Intvl,
				timestamp.Now().Sub(info.ExChgT), info.ExConseq)
		}
		minr := atomic.LoadUint64(&RunningCfg.EvRConseqRmin)
		maxr := atomic.LoadUint64(&RunningCfg.EvRConseqRmax)
		// don't report all blacklisted events, only the 1st one and
		// after some repeat values (depending on configured values)
		var report bool
		report, diff = reportBlstEv(info.ExConseq, minr, maxr)
		if !report {
			return // ignore, don't report
		}
		evrStats.Inc(evrCnts.blstSent)
	} else if info.ExConseq > 0 && info.OkConseq == 1 {
		evrStats.Inc(evrCnts.blstRec)
	}
	// fill even rate info (always)
	calltr.FillEvRateInfo(&ed.Rate, info, rv, rateMax.Max, rateMax.Intvl,
		diff)
	if !EventsRing.Add(ed) {
		ERR("Failed to add event %d: %s\n",
			evrStats.Get(evrCnts.no), ed.String())
	}
}

// per call event callback
func callEvHandler(evt calltr.EventType, ce *calltr.CallEntry,
	src, dst calltr.NetInfo) {
	var diff uint64

	evrStats.Inc(evrCnts.no)

	// check type blacklist from EvRing
	if EventsRing.Blacklisted(evt) {
		evrStats.Inc(evrCnts.blstType)
		return
	}

	ok, ridx, rv, info := EvRateBlst.IncUpdate(evt, src, timestamp.Now())
	if !ok {
		evrStats.Inc(evrCnts.trackFail)
		if DBGon() {
			DBG("max event blacklist size exceeded: %v / %v\n",
				EvRateBlst.CrtEntries(), EvRateBlst.MaxEntries())
		}
		return
	}
	_, rateMax := EvRateBlst.GetRateMax(ridx)
	if info.Exceeded {
		evrStats.Inc(evrCnts.blstRate)
		if DBGon() {
			DBG("event %s src %s blacklisted: rate %f/%f per %v,"+
				" since %v (%v times)\n",
				evt, src.IP(), rv, rateMax.Max, rateMax.Intvl,
				timestamp.Now().Sub(info.ExChgT), info.ExConseq)
		}
		minr := atomic.LoadUint64(&RunningCfg.EvRConseqRmin)
		maxr := atomic.LoadUint64(&RunningCfg.EvRConseqRmax)
		// don't report all blacklisted events, only the 1st one and
		// after some repeat values (depending on configured values)
		var report bool
		report, diff = reportBlstEv(info.ExConseq, minr, maxr)
		if !report {
			return // ignore, don't report
		}
		evrStats.Inc(evrCnts.blstSent)
	} else if info.ExConseq > 0 && info.OkConseq == 1 {
		evrStats.Inc(evrCnts.blstRec)
	}
	// fill even rate info (always)
	var evRate calltr.EvRateInfo
	calltr.FillEvRateInfo(&evRate, info, rv, rateMax.Max, rateMax.Intvl,
		diff)
	if !EventsRing.AddCallEntry(evt, ce, true /* lock */, evRate) {
		ERR("Failed to add event %d: %s\n",
			evrStats.Get(evrCnts.no), evt.String())
	}
}

// process pkt / parse error event generation handler
func pktErrEvHandler(evt calltr.EventType,
	sip net.IP, sport int, dip net.IP, dport int, proto calltr.NAddrFlags,
	callid []byte, reason []byte) {
	var diff uint64
	var src calltr.NetInfo

	evrStats.Inc(evrCnts.no)
	// check type blacklist from EvRing
	if EventsRing.Blacklisted(evt) {
		evrStats.Inc(evrCnts.blstType)
		return
	}
	src.SetIP(sip)
	src.SetProto(proto)
	ok, ridx, rv, info := EvRateBlst.IncUpdate(evt, src, timestamp.Now())
	if !ok {
		evrStats.Inc(evrCnts.trackFail)
		if DBGon() {
			DBG("max event blacklist size exceeded: %v / %v\n",
				EvRateBlst.CrtEntries(), EvRateBlst.MaxEntries())
		}
		return
	}
	_, rateMax := EvRateBlst.GetRateMax(ridx)
	if info.Exceeded {
		evrStats.Inc(evrCnts.blstRate)
		if DBGon() {
			DBG("event %s src %s blacklisted: rate %f/%f per %v,"+
				" since %v (%v times)\n",
				evt, src.IP(), rv, rateMax.Max, rateMax.Intvl,
				timestamp.Now().Sub(info.ExChgT), info.ExConseq)
		}
		minr := atomic.LoadUint64(&RunningCfg.EvRConseqRmin)
		maxr := atomic.LoadUint64(&RunningCfg.EvRConseqRmax)
		// don't report all blacklisted events, only the 1st one and
		// after some repeat values (depending on configured values)
		var report bool
		report, diff = reportBlstEv(info.ExConseq, minr, maxr)
		if !report {
			return // ignore, don't report
		}
		evrStats.Inc(evrCnts.blstSent)
	} else if info.ExConseq > 0 && info.OkConseq == 1 {
		evrStats.Inc(evrCnts.blstRec)
	}
	// fill even rate info (always)
	var evRate calltr.EvRateInfo
	calltr.FillEvRateInfo(&evRate, info, rv, rateMax.Max, rateMax.Intvl,
		diff)
	if !EventsRing.AddBasic(evt,
		sip, uint16(sport), dip, uint16(dport),
		proto, callid, reason, evRate) {
		ERR("Failed to add event %d: %s\n",
			evrStats.Get(evrCnts.no), evt.String())
	}
}

func CallTrack(m *sipsp.PSIPMsg, n [2]calltr.NetInfo) bool {
	return calltr.Track(m, n, nil /*evHandler*/)
}
