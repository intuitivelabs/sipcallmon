// Oracle / Acme sbc ipfix support (non-standard)

package sipcallmon

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/intuitivelabs/counters"
	"github.com/intuitivelabs/timestamp"
)

var acmeIPFIXconnPool = sync.Pool{
	New: func() any {
		acmeIPFIXstats.cnts.Inc(acmeIPFIXstats.hPoolConns)
		n := new(AcmeIPFIXconn)
		runtime.SetFinalizer(n, func(c *AcmeIPFIXconn) {
			acmeIPFIXstats.cnts.Dec(acmeIPFIXstats.hPoolConns)
		})
		return new(AcmeIPFIXconn)
	},
}

// AcmeIPFIXcollector listens on a socket and start processing go routines
// for each new connection (acme ipfix tcp traffic expected).
type AcmeIPFIXcollector struct {
	laddr    *net.TCPAddr
	net      string
	listener *net.TCPListener
	conns    AcmeIPFIXconnLst
	connsNo  atomic.Uint32
	gStats   *acmeIPFIXstatsT

	init     bool
	initLock sync.Mutex
	wg       sync.WaitGroup // for local go-routines
	Cfg      AcmeIPFIXconnCfg
}

func (s *AcmeIPFIXcollector) Init(addr string, port int,
	cfg AcmeIPFIXconnCfg) error {

	s.Cfg = cfg

	ipv6 := false

	if h, p, err := net.SplitHostPort(addr); err == nil {
		// addr is in host:port format -> ignore port
		WARN("ipfix_addr is in host:port format (%q),"+
			" overriding port %s with %d\n",
			addr, p, port)
		addr = h
	}

	if ip, err := netip.ParseAddr(addr); err == nil {
		ipv6 = ip.Is6()
		if ipv6 {
			s.net = "tcp6"
		} else {
			s.net = "tcp4"
		}
		addrPort := netip.AddrPortFrom(ip, uint16(port))
		s.laddr = net.TCPAddrFromAddrPort(addrPort)
	} else {
		// addr is not ip => try to resolve it
		addr = fmt.Sprintf("%s:%d", addr, port) // add port

		var t *net.TCPAddr
		if ipv6 { // if ipv6 first -> try first ipv6
			if t, err = net.ResolveTCPAddr("tcp6", addr); err == nil {
				s.laddr = t
				s.net = "tcp6"
			}
		}

		if s.laddr == nil { // not forced ipv6 or failed to resolve ipv6
			// try ipv4
			if t, err = net.ResolveTCPAddr("tcp4", addr); err == nil {
				s.laddr = t
				s.net = "tcp4"
			} else if !ipv6 { // ipv4 lookup failed and ipv6 not tried -> try it
				if t, err = net.ResolveTCPAddr("tcp6", addr); err == nil {
					s.laddr = t
					s.net = "tcp6"
				}
			}
			if s.laddr == nil {
				// failed
				return fmt.Errorf("invalid ipfix tcp listen address:"+
					" %q or port %d : %w\n",
					addr, port, err)
			}
		}
	}

	var err error
	s.initLock.Lock()
	s.conns.Init()
	s.connsNo.Store(0)
	s.wg = sync.WaitGroup{}
	s.listener, err = net.ListenTCP(s.net, s.laddr)
	if err == nil {
		s.init = true
	}
	s.initLock.Unlock()
	if err != nil {
		return fmt.Errorf("acme ipfix: failed to listen on %s:%s (%s:%d): %w",
			s.net, s.laddr, addr, port, err)
	}
	acmeIPFIXstatsLock.Lock()
	if acmeIPFIXstats == nil {
		acmeIPFIXstats = &acmeIPFIXstatsT{}
		if !acmeIPFIXstats.Init() {
			acmeIPFIXstats = nil
			acmeIPFIXstatsLock.Unlock()
			return fmt.Errorf("acme ipfix: failed to init stats\n")
		}
		s.gStats = acmeIPFIXstats
	}
	acmeIPFIXstatsLock.Unlock()
	return nil
}

func (s *AcmeIPFIXcollector) IsInit() bool {
	s.initLock.Lock()
	ret := s.init
	s.initLock.Unlock()
	return ret
}

func (s *AcmeIPFIXcollector) Start(wg *sync.WaitGroup) error {
	if !s.init {
		return fmt.Errorf("acme ipfix: failed to start: not initialised")
	}
	if wg != nil {
		wg.Add(1)
	}
	s.wg.Add(1)
	go func() {
		if wg != nil {
			defer wg.Done()
		}
		s.acceptConns(wg)
		s.Stop()
		s.wg.Done() // acceptConns go routine
		s.Wait()    // wait for all the conns go routines
	}()
	return nil
}

func (s *AcmeIPFIXcollector) Stop() bool {
	s.initLock.Lock()
	ret := s.init
	if s.init {
		if s.listener != nil {
			s.listener.Close()
		}
		s.init = false
	}
	s.initLock.Unlock()
	s.conns.Lock()
	// TODO: some close timeout?
	s.conns.ForEachUnsafe(func(c *AcmeIPFIXconn) bool {
		c.conn.Close()
		return true
	})
	s.conns.Unlock()
	return ret
}

// Wait waits for all the AcmeIPFIXcollector running go routines to
// finish.
func (s *AcmeIPFIXcollector) Wait() {
	s.wg.Wait()
}

func (s *AcmeIPFIXcollector) Addr() net.Addr {
	if s.IsInit() && s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

func (s *AcmeIPFIXcollector) ConnsNo() uint32 {
	return s.connsNo.Load()
}

// GetConnInfo will fill an AcmeIPFIXconnInfo array from the
// list of active connections, starting at connection with index
// equal to start and ending after copying "no" connections or when
// the array is full.
// It returns the number of filled elements in the array and the
// total number of connections in the list (ConnsNo()).
func (s *AcmeIPFIXcollector) GetConnInfo(info []AcmeIPFIXconnInfo,
	start int, no int) (int, int) {
	var i int
	var connsNo uint32

	if start < 0 || no <= 0 {
		return 0, int(s.ConnsNo())
	}
	s.conns.Lock()
	{
		s.conns.ForEachUnsafe(func(c *AcmeIPFIXconn) bool {
			if i < start {
				i++
				return true
			}
			if (i - start) >= no {
				return false // stop, exceeded requested number
			}
			if (i - start) < len(info) {
				c.GetInfo(&info[i-start])
			} else {
				return false // stop, no more space in info
			}
			i++
			return true
		})

		connsNo = s.connsNo.Load()
	}
	s.conns.Unlock()
	if i < start {
		return 0, int(connsNo)
	}
	return i - start, int(connsNo)
}

// NOTE: supposed to run in a go-routine, with s.wg.Add(1)
func (s *AcmeIPFIXcollector) acceptConns(wg *sync.WaitGroup) {

	connId := uint64(0)
	for {
		tcpConn, err := s.listener.AcceptTCP()
		if err == nil {
			now := timestamp.Now()
			// use sync.pool
			conn, _ := acmeIPFIXconnPool.Get().(*AcmeIPFIXconn)
			conn.Reset()
			conn.id = connId
			conn.conn = *tcpConn
			conn.startTS = now
			conn.lastIO = now
			conn.gStats = s.gStats
			conn.Cfg = s.Cfg
			/*
				conn := &AcmeIPFIXconn{
					id:      connId,
					conn:    *tcpConn,
					startTS: now,
					lastIO:  now,
					gStats:  s.gStats,
					Cfg:     s.Cfg,
				}
			*/
			s.addConn(conn)
			connId++
			s.wg.Add(1)
			go func() {
				DBG("AcmeIPFIX: conn.run() start\n")
				s.gStats.cnts.Inc(s.gStats.hActiveConns)
				s.gStats.cnts.Inc(s.gStats.hTotalConns)
				conn.run()
				DBG("AcmeIPFIX: conn.run() exit\n")
				conn.conn.Close()
				lifetime := timestamp.Now().Sub(conn.startTS) / time.Second
				s.gStats.cnts.Set(s.gStats.hMaxClifetime,
					counters.Val(lifetime))
				s.gStats.cnts.Dec(s.gStats.hActiveConns)
				s.wg.Done()
				s.rmConn(conn)
				acmeIPFIXconnPool.Put(conn)
			}()
		} else { // some error
			if errors.Is(err, net.ErrClosed) {
				// Listener was closed => clean exit
				// NOTE: net.ErrClosed available since go 1.16
				break
			}
			ERR("acme ipfix collector: listen %s\n", err)
		}
	}
}

func (s *AcmeIPFIXcollector) addConn(c *AcmeIPFIXconn) {
	s.conns.Lock()
	s.conns.InsertUnsafe(c)
	s.connsNo.Add(1)
	s.conns.Unlock()
}

func (s *AcmeIPFIXcollector) rmConn(c *AcmeIPFIXconn) {
	s.conns.Lock()
	s.conns.RmUnsafe(c)
	s.connsNo.Add(^(uint32(0))) // Dec
	s.conns.Unlock()
}
