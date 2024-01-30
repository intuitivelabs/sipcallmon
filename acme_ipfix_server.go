// Oracle / Acme sbc ipfix support (non-standard)

package sipcallmon

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// AcmeIPFIXcollector listens on a socket and start processing go routines
// for each new connection (acme ipfix tcp traffic expected).
type AcmeIPFIXcollector struct {
	laddr    *net.TCPAddr
	net      string
	listener *net.TCPListener
	conns    AcmeIPFIXconnLst
	gStats   *acmeIPFIXstatsT

	init     bool
	initLock sync.Mutex
	wg       sync.WaitGroup // for local go-routines
}

func (s *AcmeIPFIXcollector) Init(addr string, port int) error {

	ipv6 := false
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
		DBG("acceptConns: before Wait\n")
		s.wg.Done() // acceptConns go routine
		s.Wait()    // wait for all the conns go routines
		DBG("acceptConns: after Wait\n")
	}()
	return nil
}

func (s *AcmeIPFIXcollector) Stop() bool {
	DBG("AcmeIPFIXcollector::Stop entered\n")
	s.initLock.Lock()
	DBG("AcmeIPFIXcollector::Stop after Lock\n")
	ret := s.init
	if s.init {
		if s.listener != nil {
			s.listener.Close()
			DBG("AcmeIPFIXcollector::Stop after listener.Close\n")
		}
		s.init = false
	}
	s.initLock.Unlock()
	DBG("AcmeIPFIXcollector::Stop before conns.Lock\n")
	s.conns.Lock()
	// TODO: some close timeout?
	s.conns.ForEachUnsafe(func(c *AcmeIPFIXconn) bool {
		c.conn.Close()
		return true
	})
	s.conns.Unlock()
	DBG("AcmeIPFIXcollector::Stop exiting\n")
	return ret
}

// Wait waits for all the AcmeIPFIXcollector running go routines to
// finish.
func (s *AcmeIPFIXcollector) Wait() {
	s.wg.Wait()
}

// NOTE: supposed to run in a go-routine, with s.wg.Add(1)
func (s *AcmeIPFIXcollector) acceptConns(wg *sync.WaitGroup) {

	connId := uint64(0)
	for {
		tcpConn, err := s.listener.AcceptTCP()
		if err == nil {
			// TODO: use sync.pool
			conn := &AcmeIPFIXconn{
				id:     connId,
				conn:   *tcpConn,
				lastIO: time.Now(),
				gStats: s.gStats,
			}
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
				s.gStats.cnts.Dec(s.gStats.hActiveConns)
				s.wg.Done()
				s.rmConn(conn)
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
	s.conns.Unlock()
}

func (s *AcmeIPFIXcollector) rmConn(c *AcmeIPFIXconn) {
	s.conns.Lock()
	s.conns.RmUnsafe(c)
	s.conns.Unlock()
}
