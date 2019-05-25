package main

/* TODO:
          - ip defrag
		  - ip6 defrag ?
		  - tcpreassembly Flush
		  - stream alloc'ed from Pool or special list
		  - options for tcpreassembly mem. limits (pages)
		  - tcp stream re-sync support
		  - option for snap len (live capture)
		   - streams: various optimisations
*/

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers" // recommended
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"

	"andrei/sipsp"
	"andrei/sipsp/calltr"
)

import _ "net/http/pprof"

const version = "6.3"

var startTS time.Time

type pstats struct {
	n              uint64 // total packet count
	ip4            uint64
	ip6            uint64
	ip4frags       uint64
	ip6frags       uint64
	ip4defrag      uint64
	udpN           uint64
	udp4           uint64
	udp6           uint64
	tcpN           uint64
	tcp4           uint64
	tcp6           uint64
	sctpN          uint64
	sctp4          uint64
	sctp6          uint64
	tlsN           uint64
	dtlsN          uint64
	otherN         uint64
	decodeErrs     uint64
	injected       uint64
	seen           uint64 // actual packet seen (not filtered)
	sipUDP         uint64
	sipTCP         uint64
	callTrUDP      uint64
	callTrTCP      uint64
	callTrErrUDP   uint64
	callTrErrTCP   uint64
	tcpSyn         uint64
	tcpFin         uint64
	tcpClosed      uint64
	tcpIgn         uint64
	tcpStreamIgn   uint64
	tcpStreams     uint64
	tcpSegs        uint64
	tcpRcvd        uint64
	tcpOutOfOrder  uint64
	tcpMissed      uint64
	tcpMissedBytes uint64
	tcpRecovered   uint64
	tcpStreamTo    uint64 // streams closed due to timeout
	tcpExpReorder  uint64 // streams flushed of expired re-ordered data
	tooSmall       uint64
	tooBig         uint64
	errs           uint64
	errsUDP        uint64
	errsTCP        uint64
	offsetErr      uint64
	bodyErr        uint64
	ok             uint64
	reqsN          uint64
	replsN         uint64
	errType        [sipsp.ErrConvBug + 1]uint64
	method         [sipsp.MOther + 1]uint64
	repl           [9]uint64
}

var stats pstats

type mycfg struct {
	verbose        bool
	fileMode       bool
	replay         bool
	replayMinDelay time.Duration
	replayMaxDelay time.Duration
	replayScale    float64
	runForever     bool
	iface          string
	httpPort       int
	httpAddr       string
	tcpGCInt       time.Duration
	tcpReorderTo   time.Duration
	tcpConnTo      time.Duration
}

var runningCfg *mycfg

func DBG(f string, a ...interface{}) {
	//fmt.Printf("DBG: "+f, a...)
}

func main() {
	var cfg mycfg
	var wg *sync.WaitGroup

	// save actual config for global ref.
	runningCfg = &cfg

	startTS = time.Now()

	flag.BoolVar(&cfg.verbose, "verbose", false, "turn on verbose mode")
	flag.BoolVar(&cfg.fileMode, "f", false, "read packets from pcap files")
	flag.BoolVar(&cfg.replay, "replay", false, "replay packets from pcap "+
		"keeping simulating delays between packets")
	flag.StringVar(&cfg.iface, "i", "", "interface to capture packets from")
	flag.IntVar(&cfg.httpPort, "p", 0, "port for http server")
	flag.StringVar(&cfg.httpAddr, "l", "", "listen address for http server")
	flag.BoolVar(&cfg.runForever, "forever", false, "keep web server running")
	flag.Float64Var(&cfg.replayScale, "delay_scale", 0, "scale factor for inter packet "+
		"delay intervals")
	replMinDelayS := flag.String("min_delay", "250ms", "minimum delay when"+
		"replaying pcaps")
	replMaxDelayS := flag.String("max_delay", "0", "maximum delay when"+
		"replaying pcaps")
	tcpGCIntS := flag.String("tcp_gc_interval", "30s",
		"tcp garbage collection interval")
	tcpReorderToS := flag.String("tcp_reorder_timeout", "1m",
		"tcp reorder timeout")
	tcpConnToS := flag.String("tcp_connection_timeout", "60m", "tcp connection timeout")

	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr,
			"error: at least one pcap file required as argument\n")
		os.Exit(-1)
	}
	// fix cmd line params
	{
		var perr error
		errs := 0
		cfg.replayMinDelay, perr = time.ParseDuration(*replMinDelayS)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "error: invalid minimum replay delay: %s\n",
				*tcpGCIntS)
			errs++
		}
		cfg.replayMaxDelay, perr = time.ParseDuration(*replMaxDelayS)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "error: invalid maximum replay delay: %s\n",
				*tcpGCIntS)
			errs++
		}
		cfg.tcpGCInt, perr = time.ParseDuration(*tcpGCIntS)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "error: invalid tcp gc interval: %s\n",
				*tcpGCIntS)
			errs++
		}
		cfg.tcpReorderTo, perr = time.ParseDuration(*tcpReorderToS)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "error: invalid tcp gc interval: %s\n",
				*tcpReorderToS)
			errs++
		}
		cfg.tcpConnTo, perr = time.ParseDuration(*tcpConnToS)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "error: invalid tcp gc interval: %s\n",
				*tcpConnToS)
			errs++
		}
		if errs > 0 {
			os.Exit(-1)
		}
	}
	// ...

	// start web sever
	if cfg.httpPort != 0 {
		http.HandleFunc("/about", httpPrintVer)
		http.HandleFunc("/about/config", httpPrintConfig)
		http.HandleFunc("/stats", httpPrintStats)
		http.HandleFunc("/stats/raw", httpPrintStats)
		http.HandleFunc("/calls", httpCallStats)
		http.HandleFunc("/calls/list", httpCallList)
		http.HandleFunc("/inject", httpInjectMsg)
		wg = &sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", cfg.httpAddr, cfg.httpPort)
			/* ListenAndServer uses ipv6 by default if ip/host is empty
			err := http.ListenAndServe(addr, nil)
			*/
			listener, err := net.Listen("tcp4", addr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to listen on %s: %s\n",
					addr, err)
				os.Exit(-1)
			}
			err = http.Serve(listener, nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to start web server: %s\n",
					err)
				os.Exit(-1)
			}
		}()
	}
	if cfg.fileMode {
		for i := 0; i < flag.NArg(); i++ {
			processPCAP(flag.Arg(i), &cfg)
		}
	} else {
		processLive(cfg.iface, strings.Join(flag.Args(), " "), &cfg)
	}
	// print stats
	printStats(os.Stdout)
	//printStatsRaw(os.Stdout)
	if cfg.runForever && wg != nil {
		wg.Wait()
	}

}

func printStats(w io.Writer) {
	fmt.Fprintf(w, "\n\nStatistics:\n")
	fmt.Fprintf(w, "%9d packets %9d ipv4 %9d ipv6 %9d other %9d inj.\n",
		stats.n, stats.ip4, stats.ip6, stats.otherN, stats.injected)
	fmt.Fprintf(w, "%9d ip4frags %9d defrag\n",
		stats.ip4frags, stats.ip4defrag)
	fmt.Fprintf(w, "%9d udp: %9d udp4 %9d upd6\n"+
		"%9d tcp: %9d tcp4 %9d tcp6\n",
		stats.udpN, stats.udp4, stats.udp6,
		stats.tcpN, stats.tcp4, stats.tcp6)
	fmt.Fprintf(w, "%9d tls %9d dtls %9d sctp \n",
		stats.tlsN, stats.dtlsN, stats.sctpN)

	fmt.Fprintf(w, "tcp: %9d streams %9d reassembled segs"+
		" %9d total bytes \n",
		stats.tcpStreams, stats.tcpSegs, stats.tcpRcvd)
	fmt.Fprintf(w, "tcp: %9d SYNs %9d FINs %9d closed \n",
		stats.tcpSyn, stats.tcpFin, stats.tcpClosed)
	fmt.Fprintf(w, "tcp: %9d ignored %9d ignored streams\n",
		stats.tcpIgn, stats.tcpStreamIgn)
	fmt.Fprintf(w, "tcp: %9d out-of-order %9d missed %9d too big\n",
		stats.tcpOutOfOrder, stats.tcpMissed, stats.tooBig)
	fmt.Fprintf(w, "tcp: %9d missed bytes\n",
		stats.tcpMissedBytes)
	fmt.Fprintf(w, "tcp: %9d stream timeouts %9d reassembly timeouts\n",
		stats.tcpStreamTo, stats.tcpExpReorder)
	fmt.Fprintf(w, "Parsed: %9d total  %9d ok   %9d errors %9d probes\n",
		stats.seen, stats.ok, stats.errs, stats.tooSmall)
	fmt.Fprintf(w, "Parsed: %9d udp ok %9d errs %9d tcp ok %9d errs\n",
		stats.sipUDP, stats.errsUDP, stats.sipTCP, stats.errsTCP)
	fmt.Fprintf(w, "Errors: %9d parse  %9d offset mismatch %9d body\n",
		stats.errs, stats.offsetErr, stats.bodyErr)
	fmt.Fprintf(w, "Tracked: %9d udp %9d tcp %9d err udp %9d err tcp\n",
		stats.callTrUDP, stats.callTrTCP,
		stats.callTrErrUDP, stats.callTrErrTCP)

	for e := 1; e < len(stats.errType); e++ {
		if stats.errType[e] != 0 {
			fmt.Fprintf(w, "	%-30q = %9d\n",
				sipsp.ErrorHdr(e), stats.errType[e])
		}
	}
	fmt.Fprintf(w, "Requests: %d \n", stats.reqsN)
	for r := 1; r < len(stats.method); r++ {
		if stats.method[r] != 0 {
			fmt.Fprintf(w, "	%-10s = %9d\n", sipsp.SIPMethod(r), stats.method[r])
		}
	}
	fmt.Fprintf(w, "Replies: %d \n", stats.replsN)
	for i, v := range stats.repl {
		if v != 0 {
			fmt.Fprintf(w, "	%1dXX = %9d\n", i, v)
		}
	}
	fmt.Fprintln(w)
}

func printStatsRaw(w io.Writer) {
	fmt.Fprintf(w, "%s\n",
		strings.Replace(fmt.Sprintf("%+v", stats), " ", "\n", -1))
}

func httpPrintVer(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "%s version %s\n", path.Base(os.Args[0]), version)
}

func httpPrintConfig(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "%s command line arguments: %+v\n\n", os.Args[0], os.Args[1:])
	fmt.Fprintf(w, "Config:\n%s\n",

		strings.Replace(fmt.Sprintf("%+v", *runningCfg), " ", "\n", -1))

}

func httpPrintStats(w http.ResponseWriter, r *http.Request) {
	/*	fmt.Fprintf(w, "<html><head>\n")
		fmt.Fprintf(w, "<title>SIP Parse Statistics</title>\n")
		fmt.Fprintf(w, "<meta http-equiv=\"refresh\" content=\"3\">\n")
		fmt.Fprintf(w, "</head>\n")
		fmt.Fprintf(w, "<body>\n")
	*/
	//fmt.Fprintf(w, "[%s]\n", html.EscapeString(r.URL.Path))
	if r.URL.Path == "/stats/raw" {
		printStatsRaw(w)
	} else {
		fmt.Fprintf(w, "uptime: %s\n", time.Now().Sub(startTS))
		printStats(w)
	}
	/*
		fmt.Fprintf(w, "</body>\n")
	*/
}

func httpCallStats(w http.ResponseWriter, r *http.Request) {
	var stats calltr.HStats
	calltr.StatsHash(&stats)
	fmt.Fprintf(w, "CallTracking Hash Stats: %+v\n", stats)
	fmt.Fprintf(w, "Memory Stats: %+v\n", calltr.CallEntryAllocStats)
}

func httpCallList(w http.ResponseWriter, r *http.Request) {
	n := 100 // default
	s := 0
	tst := ""
	opName := ""
	operand := calltr.FilterNone
	var re *regexp.Regexp

	paramN := r.URL.Query()["n"]
	paramS := r.URL.Query()["s"]
	cmpSrc := map[string]int{
		"cid":   calltr.FilterCallID,
		"ftag":  calltr.FilterFromTag,
		"ttag":  calltr.FilterToTag,
		"key":   calltr.FilterCallKey,
		"state": calltr.FilterState,
	}
	for k, v := range cmpSrc {
		p := r.URL.Query()[k]
		if len(p) > 0 && len(p[0]) > 0 {
			// we support only one filter operand
			tst = p[0]
			operand = v
			opName = k
			break
		}
	}
	paramRe, isRe := r.URL.Query()["re"]
	if len(paramN) > 0 {
		if i, err := strconv.Atoi(paramN[0]); err == nil {
			n = i
		} else {
			fmt.Fprintf(w, "Error: n is non-number %q: %s\n", paramN[0], err)
		}
	}
	if len(paramS) > 0 && len(paramS[0]) > 0 {
		if i, err := strconv.Atoi(paramS[0]); err == nil {
			s = i
		} else {
			fmt.Fprintf(w, "Error: s is non-number %q: %s\n", paramS[0], err)
		}
	}
	if len(paramRe) > 0 {
		if i, err := strconv.Atoi(paramRe[0]); err == nil {
			if i > 0 {
				isRe = true
			} else {
				isRe = false
			}
		}
	}
	if isRe && len(tst) > 0 {
		var err error
		re, err = regexp.CompilePOSIX(tst)
		if err != nil {
			fmt.Fprintf(w, "Error bad regexp %q: %s\n", tst, err)
			return
		}
	}
	fmt.Fprintf(w, "Calls List (filter: from %d max %d matches,"+
		" match %s against %q regexp %v):\n",
		s, n, opName, tst, isRe)
	calltr.PrintCallsFilter(w, s, n, operand, []byte(tst), re)
}

var ipLocalhost net.IP = net.IP{127, 0, 0, 1}

func httpInjectMsg(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		fmt.Fprintln(w, httpHeader, injectForm, httpFooter)
	case "POST":
		if err := r.ParseForm(); err != nil {
			fmt.Fprintf(w, "Error ParseForm(): %v", err)
			return
		}
		msgformat := r.FormValue("crlfformat")
		//proto := r.FormValue("proto")
		msg := r.FormValue("sipmsg")
		verbose := false
		verboseStr := r.FormValue("verbose")
		if strings.EqualFold(verboseStr, "yes") {
			verbose = true
		}
		rawmsg, err := unescapeMsg(msg, msgformat)
		if err != nil {
			fmt.Fprintf(w, "Error unescaping message: %v", err)
			return
		}
		fmt.Fprintln(w, httpHeader)
		fmt.Fprintln(w, "<xmp>")
		//fmt.Fprintln(w, "<textarea rows=\"10\" cols=\"120\" readonly>")
		stats.injected++
		stats.seen++
		ok := udpSIPMsg(w, rawmsg, int(stats.injected)-1,
			&ipLocalhost, 5060,
			&ipLocalhost, 5060, verbose)
		if !verbose {
			fmt.Fprintf(w, "%q\n\n", rawmsg)
		}
		if ok {
			// quick hack to display the injected call (if any)
			var sipmsg sipsp.PSIPMsg
			_, err := sipsp.ParseSIPMsg(rawmsg, 0, &sipmsg,
				sipsp.SIPMsgNoMoreDataF)
			if err == 0 && sipmsg.PV.Callid.Parsed() {
				fmt.Fprintf(w, "filtering callid %q\n", sipmsg.PV.Callid.CallID.Get(sipmsg.Buf))
				calltr.PrintCallsFilter(w, 0, 1000, calltr.FilterCallID,
					sipmsg.PV.Callid.CallID.Get(sipmsg.Buf), nil)
			}
		}
		//fmt.Fprintln(w, "</textarea>")
		fmt.Fprintln(w, "</xmp>")
		fmt.Fprintln(w, injectForm)
		fmt.Fprintln(w, httpFooter)
	default:
		fmt.Fprintf(w, "method %v not supported\n", r.Method)
	}
}

func processPCAP(fname string, cfg *mycfg) {
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
	//packetSrc := gopacket.NewPacketSource(h, h.LinkType())
	//processPacketsSlow(packetSrc, cfg, true)
	processPackets(h, cfg, cfg.replay)
}

func processLive(iface, bpf string, cfg *mycfg) {

	var h *pcap.Handle
	var err error
	// TODO: option for snap len
	// wait forever: pcap.BlockForever
	timeout := cfg.tcpGCInt
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

func printPacket(w io.Writer, cfg *mycfg, n int, sip, dip *net.IP, sport, dport int, name string, l int) {
	if cfg.verbose {
		fmt.Fprintf(w, "%d. %s:%d -> %s:%d %s	payload len: %d\n",
			n, sip, sport, dip, dport, name, l)
	}
}

func printTLPacket(w io.Writer, cfg *mycfg, n int, ipl gopacket.NetworkLayer,
	trl gopacket.TransportLayer) {
	if cfg.verbose {
		fmt.Fprintf(w, "%d. %s:%s -> %s:%s %s	payload len: %d\n",
			n, ipl.NetworkFlow().Src(), trl.TransportFlow().Src(),
			ipl.NetworkFlow().Dst(), trl.TransportFlow().Dst(),
			trl.LayerType(), len(trl.LayerPayload()))
	}
}

func processPackets(h *pcap.Handle, cfg *mycfg, replay bool) {
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
	case layers.LinkTypeLoop:
		layerType = layers.LayerTypeLoopback
	case layers.LinkTypeIPv4:
		layerType = layers.LayerTypeIPv4
	case layers.LinkTypeIPv6:
		layerType = layers.LayerTypeIPv6
	default: // fallback
		layerType = h.LinkType().LayerType()
	}
	if cfg.verbose {
		fmt.Printf("LinkType %s => layerType %s)\n", h.LinkType(),
			layerType)
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
		SIPStreamOptions{Verbose: cfg.verbose, W: os.Stdout}
	tcpStreamPool := tcpassembly.NewStreamPool(tcpStreamFactory)
	tcpAssembler := tcpassembly.NewAssembler(tcpStreamPool)
	// TODO: config options
	tcpAssembler.MaxBufferedPagesTotal = 1024 * 25
	tcpAssembler.MaxBufferedPagesPerConnection = 256

	tcpGCRun := time.Now().Add(cfg.tcpGCInt)
	var last time.Time
nextpkt:
	for {
		now := time.Now()
		if cfg.tcpGCInt > 0 && now.After(tcpGCRun) {
			tcpGCRun = now.Add(cfg.tcpGCInt)
			flushed, closed := tcpAssembler.FlushWithOptions(
				tcpassembly.FlushOptions{
					T:        now.Add(-cfg.tcpConnTo),
					CloseAll: true,
				})
			stats.tcpExpReorder += uint64(flushed)
			stats.tcpStreamTo += uint64(closed)
			flushed, closed = tcpAssembler.FlushWithOptions(
				tcpassembly.FlushOptions{
					T:        now.Add(-cfg.tcpReorderTo),
					CloseAll: false,
				})
			stats.tcpExpReorder += uint64(flushed)
			stats.tcpStreamTo += uint64(closed)

		}
		buf, ci, err := h.ZeroCopyReadPacketData()
		if err != nil {
			switch err {
			case pcap.NextErrorNoMorePackets, io.EOF:
				break nextpkt // EOF
			case pcap.NextErrorTimeoutExpired:
				// garbage collection timeout (handled above)
				// do nothing, skip loop
				DBG("pcap timeout, buf =%p time %s\n", buf, now)
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
		if cfg.verbose {
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
				sport = int(udp.DstPort)
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
				if udp.SrcPort != 5060 && udp.DstPort != 5060 {
					if cfg.verbose {
						fmt.Printf("ignoring...\n\n")
					}
					break nextlayer
				}
				/*? check if udp truncated: parser.Truncated ? */
				/*
					if parser.Truncated {
						fmt.Printf("udp packet %d truncated\n", n)
					}
				*/
				stats.seen++
				var payload []byte = tl.LayerPayload()
				udpSIPMsg(os.Stdout, payload, n, &sip, sport, &dip, dport,
					cfg.verbose)
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
				DBG("DBG: %q\n", tcp.Payload)
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
				sport = int(sctp.DstPort)
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
				if cfg.verbose {
					fmt.Printf("ignoring SCTP for now...\n\n")
				}
			case layers.LayerTypeTLS:
				if tl == &tcp {
					stats.tlsN++
				} else {
					stats.dtlsN++
				}
				if cfg.verbose {
					fmt.Printf("ignoring TLS for now...\n\n")
				}
			}
		}
		if tl == nil {
			stats.otherN++
		}

		if replay {
			ts := ci.Timestamp
			if !last.IsZero() {
				wait := ts.Sub(last)
				DBG("replay: wait %s\n", wait)
				if cfg.replayScale > 0 {
					wait = time.Duration(uint64(float64(wait) * cfg.replayScale))
					DBG("replay: wait scaled to %s\n", wait)
				}
				if cfg.replayMinDelay > wait {
					wait = cfg.replayMinDelay
				}
				if cfg.replayMaxDelay != 0 && wait > cfg.replayMaxDelay {
					wait = cfg.replayMaxDelay
				}
				DBG("replay: final %s\n", wait)
				if wait > 0 {
					time.Sleep(wait)
				}
			}
			last = ts
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

/*
func processPacketsSlow(packetSrc *gopacket.PacketSource, cfg *mycfg, replay bool) {
	n := 0
	for pkt := range packetSrc.Packets() {
		n++
		stats.n++
		fmt.Printf("%d. decoded layers: ", n)
		for _, l := range pkt.Layers() {
			fmt.Printf("%q ", l.LayerType())
		}
		fmt.Println()
		ll := pkt.LinkLayer()
		if ll == nil {
			if cfg.verbose {
				fmt.Printf("packet %d with empty link layer...\n", n)
			}
			continue
		}
		llsrc, lldst := ll.LinkFlow().Endpoints()
		nl := pkt.NetworkLayer() // ip
		if nl == nil {
			if cfg.verbose {
				fmt.Printf("packet %d  %s - %s no network layer (non-IP?)\n",
					n, llsrc, lldst)
			}
			continue
		}
		nlsrc, nldst := nl.NetworkFlow().Endpoints()
		tl := pkt.TransportLayer()
		if tl == nil {
			if cfg.verbose {
				fmt.Printf("packet %d  %s - %s  %s - %s no transport layer\n",
					n, llsrc, lldst, nlsrc, nldst)
			}
			continue
		}
		tlsrc, tldst := tl.TransportFlow().Endpoints()
			// TODO: ignore app layer, unreliable at least on UDP
		var sport, dport int
		switch tl.LayerType() {
		case layers.LayerTypeUDP:
			stats.udpN++
			udp, _ := tl.(*layers.UDP)
			//fmt.Printf("udp %d -> %d\n", udp.SrcPort, udp.DstPort)
			if cfg.verbose {
				fmt.Printf("%d. %s:%d -> %s:%d UDP	payload len: %d\n",
					n, nlsrc, udp.SrcPort, nldst, udp.DstPort,
					len(udp.LayerPayload()))
			}
			if udp.SrcPort != 5060 && udp.DstPort != 5060 {
				if cfg.verbose {
					fmt.Printf("ignoring...\n\n")
				}
				continue
			}
			sport = int(udp.SrcPort)
			dport = int(udp.DstPort)
		case layers.LayerTypeTCP:
			stats.tcpN++
			if cfg.verbose {
				tcp, _ := tl.(*layers.TCP)
				fmt.Printf("%d. %s:%d -> %s:%d TCP	payload len: %d\n",
					n, nlsrc, tcp.SrcPort, nldst, tcp.DstPort,
					len(tcp.LayerPayload()))
				fmt.Printf("ignoring TCP for now...\n\n")
			}
			continue
		default:
			stats.otherN++
			if cfg.verbose {
				fmt.Printf("unknown, unsupported\n")
				fmt.Printf("%d. %s:%s -> %s:%s %s(?)	len: %d %d\n",
					n, nlsrc, tlsrc, nldst, tldst, tl.LayerType(),
					len(tl.LayerContents()), len(tl.LayerPayload()))
				fmt.Printf("ignoring unsupported transport...\n\n")
				// fmt.Printf("%q\n\n", tl.LayerPayload()
				// ApplicationLayer does not seem to be reliable.
				// use NetworkLayer.LayerPayload instead
			}
			continue
		}
		stats.seen++
		var buf []byte = tl.LayerPayload()
		processSIPMsg(os.Stdout, buf, n, nlsrc.String(), sport,
			nldst.String(), dport, cfg.verbose)
		if replay && cfg.replayMinDelay > 0 {
			time.Sleep(time.Duration(cfg.replayMinDelay) / time.Millisecond)
		}
	}
}
*/

func udpSIPMsg(w io.Writer, buf []byte, n int, sip *net.IP, sport int, dip *net.IP, dport int, verbose bool) bool {
	ret := true
	if verbose {
		fmt.Fprintf(w, "%q\n", buf)
	}
	var sipmsg sipsp.PSIPMsg
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
					sipmsg.PV.CLen.Len, int(sipmsg.Body.Len),
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
	evCnt++
	//fmt.Printf("Event %d: %s\n", evCnt, ed.String())
	if !eventsRing.Add(ed) {
		fmt.Fprintf(os.Stderr, "Failed to add event %d: %s\n",
			evCnt, ed.String())
	}
}

func CallTrack(m *sipsp.PSIPMsg, n *[2]calltr.NetInfo) bool {
	return calltr.Track(m, n, evHandler)
}

func unescapeMsg(msg string, format string) ([]byte, error) {
	m := []byte(msg)
	f := strings.ToLower(format)
	if f == "auto" {
		if bytes.Count(m, []byte("\\r\\n")) > 5 {
			f = "escaped"
		} else if bytes.Count(m, []byte(".\r\n")) > 5 {
			f = "ngrepcrlf"
		} else if bytes.Count(m, []byte("\r\n")) > 5 {
			f = "crlf"
		} else if bytes.Count(m, []byte(".\n")) > 5 {
			f = "ngreplf"
		} else if bytes.Count(m, []byte(".\r")) > 5 {
			f = "ngrepcr"
		} else if bytes.Count(m, []byte("\n")) > 5 {
			f = "lf"
		} else if bytes.Count(m, []byte("\\n")) > 5 {
			if n, err := unescapeMsg(msg, "escaped"); err == nil {
				format = "lf"
				m = n
			} else {
				return nil, err
			}
		} else {
			f = "auto"
		}
	}
	switch f {
	case "crlf":
		// do nothing
	case "lf":
		m = bytes.Replace(m, []byte("\n"), []byte("\r\n"), -1)
	case "ngreplf":
		unescapeNgrep(&m)
		//m = bytes.Replace(m, []byte(".\n"), []byte("\r\n"), -1)
	case "ngrepcr":
		unescapeNgrep(&m)
		//m = bytes.Replace(m, []byte(".\r"), []byte("\r\n"), -1)
	case "ngrepcrlf":
		unescapeNgrep(&m)
		//m = bytes.Replace(m, []byte(".\r\n"), []byte("\r\n"), -1)
	case "escaped":
		unescapeBSlice(&m)
	default:
		return nil, fmt.Errorf("unknown message format %q", format)
	}
	return m, nil
}

func unescapeNgrep(b *[]byte) {
	buf := *b
	j := 0
	for i := 0; i < len(buf); i++ {
		switch buf[i] {
		case '.':
			if i+2 < len(buf) && buf[i+1] == '\r' && buf[i+2] == '\n' {
				buf[j], buf[j+1] = '\r', '\n'
				j += 2
				i += 2 // skip over next 2 chars
				continue
			} else if i+1 < len(buf) && (buf[i+1] == '\r' || buf[i+1] == '\n') {
				buf[j], buf[j+1] = '\r', '\n'
				j += 2
				i += 1 // skip over next char
				continue
			}
		case '\n', '\r':
			// delete \n or \r not prefixed by '.'
			continue
		}
		buf[j] = buf[i]
		j++
	}
	*b = buf[:j]
}

// in-place !
// expects a string with CRLF escaped. Real CR LF (unescaped) will be
// deleted. Escaped CRLF will be replaced with the real char.
// Same for other standard escapes (\t, \", \hh ...).
func unescapeBSlice(b *[]byte) {
	bs := false
	buf := *b
	j := 0
	for i := 0; i < len(buf); i++ {
		if bs {
			switch buf[i] {
			case 'n':
				buf[j] = '\n'
			case 'r':
				buf[j] = '\r'
			case 'a':
				buf[j] = '\a'
			case 'b':
				buf[j] = '\b'
			case 't':
				buf[j] = '\t'
			case 'v':
				buf[j] = '\v'
			case '\\':
				buf[j] = '\\'
			case '"':
				buf[j] = '"'
			case 'x':
				if i+3 <= len(buf) {
					hex.Decode(buf[j:j+1], buf[i+1:i+3])
					i += 2 // skip over the next 2 chars
				}
			default:
				buf[j] = buf[i]
			}
			j++
			bs = false
		} else if buf[i] == '\\' {
			bs = true
		} else if buf[i] != '\n' && buf[i] != '\r' {
			// skip over real CR or LF
			buf[j] = buf[i]
			j++
		}
	}
	*b = buf[:j]
}

var httpHeader string = `
<!DOCTYPE html>
<html>
<body>
`

var httpFooter string = `
</body>
</html>

`
var injectForm string = `

<h2>Inject Packet</h2>

<p>Paste a sip packet (ascii text)</p>

<form action="#" method="post">
	<p>Line termination format and protocol:</p>
	<select name="crlfformat">
		<option value="auto">auto detect</option>
		<option value="ngreplf">ngrep .LF</option>
		<option value="ngrepcr">ngrep .CR</option>
		<option value="ngrepcrlf">ngrep .CRLF</option>
		<option value="lf">LF standard UNIX editor</option>
		<option value="crlf">standard raw CRLF</option>
		<option value="escaped">one line \r\n escaped</option>
	</select>
	<select name="proto">
		<option value="udp">UDP</option>
		<option value="tcp">TCP</option>
		<option value="tls">TLS</option>
	</select>
	<br>
	<p> Verbose:</p>
	<select name="verbose">
		<option value="yes">Yes</option>
		<option value="no" selected>No</option>
	</select>
	<br>
	<p>SIP message</p>
	<br>
	<textarea name="sipmsg" rows="25" cols="80" wrap="off">
	</textarea>
	<br>
	<input type="submit">
</form>

`
