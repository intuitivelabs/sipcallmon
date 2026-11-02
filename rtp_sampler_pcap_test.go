package sipcallmon

import (
	"bufio"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// TestRTPSamplePcapSize replays per call captures through the RTP sampler
// and logs the pcap dump size with and without sampling.
// It runs only if SIPCM_RTP_SAMPLE_PCAPS is set to a space separated list
// of pcap or pcapng files, each holding one call (the call-id is the file
// name). UDP payloads that do not look like RTP v2 or RTCP but start with a
// letter are counted as SIP and always written. RTCP is counted apart:
// sipcallmon matches media by the SDP destination, so RTCP on port+1 never
// reaches the dump, only rtcp-mux would. Sizes use the dump format:
// 16 bytes record header + synthetic ethernet/IP/UDP header + payload.
// Example:
//
//	SIPCM_RTP_SAMPLE_PCAPS="/tmp/a.pcapng /tmp/b.pcap" go test -v \
//	  -run RTPSamplePcapSize
func TestRTPSamplePcapSize(t *testing.T) {
	files := strings.Fields(os.Getenv("SIPCM_RTP_SAMPLE_PCAPS"))
	if len(files) == 0 {
		t.Skip("SIPCM_RTP_SAMPLE_PCAPS not set")
	}
	for _, n := range []uint32{10, 50} {
		var totAll, totSampled int
		for _, fn := range files {
			all, sampled, rtp, rtpW, rtcp, dur := tSamplePcap(t, fn, n)
			t.Logf("N=%d %s: %.1f min, rtp %d -> %d pkts,"+
				" size w/o rtcp %d -> %d bytes (%.1f%% saved),"+
				" rtcp %d bytes",
				n, fn, dur.Minutes(), rtp, rtpW, all, sampled,
				100*float64(all-sampled)/float64(all), rtcp)
			totAll += all
			totSampled += sampled
		}
		t.Logf("N=%d total: %d -> %d bytes (%.1f%% saved)", n,
			totAll, totSampled,
			100*float64(totAll-totSampled)/float64(totAll))
	}
}

type tPktSrc interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
}

func tSamplePcap(t *testing.T, fn string, maxPkts uint32) (all, sampled,
	rtp, rtpW, rtcp int, dur time.Duration) {
	f, err := os.Open(fn)
	if err != nil {
		t.Fatalf("open %s: %s", fn, err)
	}
	defer f.Close()
	r := bufio.NewReader(f)
	magic, err := r.Peek(4)
	if err != nil {
		t.Fatalf("read %s: %s", fn, err)
	}
	var src tPktSrc
	if string(magic) == "\x0a\x0d\x0d\x0a" {
		src, err = pcapgo.NewNgReader(r, pcapgo.DefaultNgReaderOptions)
	} else {
		src, err = pcapgo.NewReader(r)
	}
	if err != nil {
		t.Fatalf("pcap reader %s: %s", fn, err)
	}
	s := NewRTPSampler(maxPkts, defaultConfigVals.WpcapRTPIdle,
		defaultConfigVals.WpcapRTPStrms)
	var first, last time.Time
	for {
		data, ci, err := src.ReadPacketData()
		if err == io.EOF {
			break
		} else if err != nil {
			t.Logf("%s: stopped reading: %s", fn, err)
			break
		}
		pkt := gopacket.NewPacket(data, src.LinkType(), gopacket.NoCopy)
		nl := pkt.NetworkLayer()
		udp, _ := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if nl == nil || udp == nil {
			continue
		}
		var sip, dip []byte
		hlen := 16 + 14 + 8
		switch ip := nl.(type) {
		case *layers.IPv4:
			sip, dip = ip.SrcIP, ip.DstIP
			hlen += 20
		case *layers.IPv6:
			sip, dip = ip.SrcIP, ip.DstIP
			hlen += 40
		default:
			continue
		}
		if first.IsZero() {
			first = ci.Timestamp
		}
		last = ci.Timestamp
		p := udp.Payload
		sz := hlen + len(p)
		kind, _, _ := rtpSampleClassify(p)
		if kind == rtpSampleRTCP {
			rtcp += sz
			continue
		}
		all += sz
		if kind == rtpSampleOther && len(p) > 0 &&
			(p[0] >= 'A' && p[0] <= 'Z' || p[0] >= 'a' && p[0] <= 'z') {
			sampled += sz // SIP
			continue
		}
		rtp++
		if s.Sample([]byte(fn), sip, int(udp.SrcPort), dip,
			int(udp.DstPort), p, ci.Timestamp) == RTPSampleWrite {
			sampled += sz
			rtpW++
		}
	}
	return all, sampled, rtp, rtpW, rtcp, last.Sub(first)
}
