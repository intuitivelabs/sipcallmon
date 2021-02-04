// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipcallmon

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/intuitivelabs/calltr"
)

type Config struct {
	Verbose        bool          `config:"verbose"`
	PCAPs          string        `config:"pcap"`
	Replay         bool          `config:"replay"`
	ReplayMinDelay time.Duration `config:"replay_min_delay"`
	ReplayMaxDelay time.Duration `config:"replay_max_delay"`
	ReplayScale    float64       `config:"replay_scale"`
	RunForever     bool          `config:"run_forever"`
	Iface          string        `config:"iface"`
	BPF            string        `config:"bpf"` // packet filter
	HTTPport       int           `config:"http_port"`
	HTTPaddr       string        `config:"http_addr"`
	TCPGcInt       time.Duration `config:"tcp_gc_int"`
	TCPReorderTo   time.Duration `config:"tcp_reorder_timeout"`
	TCPConnTo      time.Duration `config:"tcp_connection_timeout"`
	MaxBlockedTo   time.Duration `config:"max_blocked_timeout"`
	EvBufferSz     int           `config:"event_buffer_size"`
	// maximum entries in the rate blacklist table.
	EvRblstMax uint `config:"event_rate_max_sz"`
	// ev rate blacklist max values for each rate
	EvRblstMaxVals [calltr.NEvRates]float64 `config:"event_rate_values"`
	// ev rate blacklist time intervals for each rate
	EvRblstIntvls [calltr.NEvRates]time.Duration `config:"event_rate_intervals"`
	// ev rate periodic GC config. Note that there are 3 GC types for
	// the ev rate entries: periodic GC, hard GC run when max_entries is
	// exceeded an a new entry needs to be allocated and light GC run also
	// on allocation, when some limit is exceeded
	// For now only the periodic GC can be configured (the other two are
	// hard-wired and can be changed only via the web interface).

	// ev rate periodic GC interval
	EvRgcInterval time.Duration `config:"evr_gc_interval"`
	// ev rate old age: entries that are no blacklisted and
	//  matched a message more then this interval ago will be GCed
	EvRgcOldAge time.Duration `config:"evr_gc_old_age"`
	// ev rate periodic GC maximum runtime (each GC run will stop after
	// this interval has elapsed)
	EvRgcMaxRunT time.Duration `config:"evr_gc_max_run_time"`
	// ev rate periodic GC target: each GC run will stop if the
	// remaining entries <= then this value
	EvRgcTarget uint `config:"evr_gc_target"`

	// call tracing options
	RegDelta uint `config:"reg_exp_delta"` // seconds
	// contact matching options
	ContactIgnorePort bool `config:"contact_ignore_port"`
}

var defaultConfigVals = Config{
	ReplayMinDelay:    250 * time.Millisecond,
	ReplayMaxDelay:    0,
	TCPGcInt:          30 * time.Second,
	TCPReorderTo:      60 * time.Second,
	TCPConnTo:         3600 * time.Second,
	MaxBlockedTo:      1 * time.Second,
	EvBufferSz:        10240,
	EvRblstMax:        1024 * 1024,
	EvRgcInterval:     10 * time.Second,
	EvRgcOldAge:       300 * time.Second,
	EvRgcMaxRunT:      1 * time.Second,
	EvRgcTarget:       10, // 10? entries
	RegDelta:          30, // seconds
	ContactIgnorePort: false,
}

var DefaultMaxRates = calltr.EvRateMaxes{
	{100, time.Second}, // max 100 evs per s
	{240, time.Minute},
	{3600, time.Hour},
}

func GetDefaultCfg() Config {
	cfg := defaultConfigVals
	for i, v := range DefaultMaxRates {
		cfg.EvRblstMaxVals[i] = v.Max
		cfg.EvRblstIntvls[i] = v.Intvl
	}
	return cfg
}

// FromOsArgs intializes and returns a config from cmd line args and
// passed default config (c).
func CfgFromOSArgs(c *Config) (Config, error) {
	var cfg Config
	var evRmaxVals string
	var evRIntvls string

	// fill default value strings (for the help msg)
	defaultEvRmaxVals := ""
	defaultEvRIntvls := ""
	for i, v := range c.EvRblstMaxVals {
		if i != 0 {
			defaultEvRmaxVals += ","
		}
		defaultEvRmaxVals += strconv.FormatFloat(v, 'f', -1, 64)
	}
	for i, v := range c.EvRblstIntvls {
		if i != 0 {
			defaultEvRIntvls += ","
		}
		defaultEvRIntvls += v.String()
	}

	// initialize cfg with the default config, just in case there is
	// some option that is not configurable via the command line
	// (missing flag with default value)
	cfg = *c

	flag.BoolVar(&cfg.Verbose, "verbose", c.Verbose, "turn on verbose mode")
	flag.StringVar(&cfg.PCAPs, "pcap", c.PCAPs, "read packets from pcap files")
	flag.StringVar(&cfg.BPF, "bpf", c.BPF, "berkley packet filter for capture")
	flag.BoolVar(&cfg.Replay, "replay", c.Replay, "replay packets from pcap "+
		"keeping simulating delays between packets")
	flag.StringVar(&cfg.Iface, "i", c.Iface,
		"interface to capture packets from")
	flag.IntVar(&cfg.HTTPport, "p", c.HTTPport,
		"port for http server, 0 == disable")
	flag.StringVar(&cfg.HTTPaddr, "l", c.HTTPaddr,
		"listen address for http server")
	flag.BoolVar(&cfg.RunForever, "forever", c.RunForever,
		"keep web server running")
	flag.Float64Var(&cfg.ReplayScale, "delay_scale", c.ReplayScale,
		"scale factor for inter packet delay intervals")
	replMinDelayS := flag.String("min_delay", c.ReplayMaxDelay.String(),
		"minimum delay when replaying pcaps")
	replMaxDelayS := flag.String("max_delay", c.ReplayMaxDelay.String(),
		"maximum delay when replaying pcaps")
	tcpGCIntS := flag.String("tcp_gc_interval", c.TCPGcInt.String(),
		"tcp garbage collection interval")
	tcpReorderToS := flag.String("tcp_reorder_timeout", c.TCPReorderTo.String(),
		"tcp reorder timeout")
	tcpConnToS := flag.String("tcp_connection_timeout", c.TCPConnTo.String(),
		"tcp connection timeout")
	maxBlockedToS := flag.String("max_blocked_timeout",
		c.MaxBlockedTo.String(),
		"maximum blocked timeout")
	flag.IntVar(&cfg.EvBufferSz, "event_buffer_size", c.EvBufferSz,
		"how many events will be buffered")
	flag.UintVar(&cfg.EvRblstMax, "event_rate_max_sz", c.EvRblstMax,
		"maximum number for the event rate based blacklist table")
	flag.StringVar(&evRmaxVals, "event_rate_values", defaultEvRmaxVals,
		"event rate max values list, comma or space separated")
	flag.StringVar(&evRIntvls, "event_rate_intervals", defaultEvRIntvls,
		"event rate intervals list, comma or space separated")
	evRgcIntervalS := flag.String("evr_gc_interval",
		c.EvRgcInterval.String(), "event rate periodic GC interval")
	evRgcOldAgeS := flag.String("evr_gc_old_age",
		c.EvRgcOldAge.String(),
		"event rate old age: non-blst. entries idle for more then this value"+
			" will be GCed")
	evRgcMaxRunS := flag.String("evr_gc_max_run_time",
		c.EvRgcMaxRunT.String(), "maximum runtime for each periodic GC run")
	flag.UintVar(&cfg.EvRgcTarget, "evr_gc_target", c.EvRgcTarget,
		"event rate periodic GC target: GC will stop if the number off"+
			" remaining entries is less then this value")

	flag.UintVar(&cfg.RegDelta, "reg_exp_delta", c.RegDelta,
		"extra REGISTER expiration delta for absorbing delayed re-REGISTERs")
	flag.BoolVar(&cfg.ContactIgnorePort, "contact_ignore_port",
		c.ContactIgnorePort,
		"ignore port number when comparing contacts (but not AORs)")

	flag.Parse()
	// fix cmd line params
	{
		var perr error
		errs := 0
		cfg.ReplayMinDelay, perr = time.ParseDuration(*replMinDelayS)
		if perr != nil {
			e := fmt.Errorf("invalid minimum replay delay: %s: %v",
				*tcpGCIntS, perr)
			errs++
			return cfg, e
		}
		cfg.ReplayMaxDelay, perr = time.ParseDuration(*replMaxDelayS)
		if perr != nil {
			e := fmt.Errorf("invalid maximum replay delay: %s: %v",
				*tcpGCIntS, perr)
			errs++
			return cfg, e
		}
		cfg.TCPGcInt, perr = time.ParseDuration(*tcpGCIntS)
		if perr != nil {
			e := fmt.Errorf("invalid tcp gc interval: %s: %v\n",
				*tcpGCIntS, perr)
			errs++
			return cfg, e
		}
		cfg.TCPReorderTo, perr = time.ParseDuration(*tcpReorderToS)
		if perr != nil {
			e := fmt.Errorf("invalid tcp gc interval: %s: %v\n",
				*tcpReorderToS, perr)
			errs++
			return cfg, e
		}
		cfg.TCPConnTo, perr = time.ParseDuration(*tcpConnToS)
		if perr != nil {
			e := fmt.Errorf("invalid tcp gc interval: %s: %v",
				*tcpConnToS, perr)
			errs++
			return cfg, e
		}
		cfg.MaxBlockedTo, perr = time.ParseDuration(*maxBlockedToS)
		if perr != nil {
			e := fmt.Errorf("invalid maximum blocked timeout: %s: %v",
				*maxBlockedToS, perr)
			errs++
			return cfg, e
		}

		// parse the ev rate blacklist max and intervals lists
		// function to check for valid separators
		checkSep := func(r rune) bool {
			if r == rune(',') || r == rune('|') || unicode.IsSpace(r) {
				return true
			}
			return false
		}
		cfg.EvRblstMaxVals = c.EvRblstMaxVals
		rate_vals := strings.FieldsFunc(evRmaxVals, checkSep)
		for i, s := range rate_vals {
			if i < len(cfg.EvRblstMaxVals) {
				if v, perr := strconv.ParseFloat(s, 64); perr == nil {
					cfg.EvRblstMaxVals[i] = v
				} else {
					e := fmt.Errorf("invalid rate max[%d]: %q in %q",
						i, s, evRmaxVals)
					errs++
					return cfg, e
				}
			} else {
				if i == (len(rate_vals)-1) && len(s) == 0 {
					// allow strings ending in ','
					break
				}
				e := fmt.Errorf("too many rate max values: %d (max %d) in %q",
					len(rate_vals), len(cfg.EvRblstMaxVals),
					evRmaxVals)
				errs++
				return cfg, e
			}
		}
		cfg.EvRblstIntvls = c.EvRblstIntvls
		rate_intvls := strings.FieldsFunc(evRIntvls, checkSep)
		for i, s := range rate_intvls {
			if i < len(cfg.EvRblstIntvls) {
				if v, perr := time.ParseDuration(s); perr == nil {
					cfg.EvRblstIntvls[i] = v
				} else {
					e := fmt.Errorf("invalid rate interval[%d]: %q in %q",
						i, s, evRIntvls)
					errs++
					return cfg, e
				}
			} else {
				if i == (len(rate_intvls)-1) && len(s) == 0 {
					// allow strings ending in ','
					break
				}
				e := fmt.Errorf("too many rate interval values:"+
					" %d (max %d) in %q",
					len(rate_intvls), len(cfg.EvRblstIntvls), evRIntvls)
				errs++
				return cfg, e
			}
		}

		cfg.EvRgcInterval, perr = time.ParseDuration(*evRgcIntervalS)
		if perr != nil {
			e := fmt.Errorf("invalid evr_gc_interval: %s: %v",
				*evRgcIntervalS, perr)
			errs++
			return cfg, e
		}
		cfg.EvRgcOldAge, perr = time.ParseDuration(*evRgcOldAgeS)
		if perr != nil {
			e := fmt.Errorf("invalid evr_gc_old_age: %s: %v",
				*evRgcOldAgeS, perr)
			errs++
			return cfg, e
		}
		cfg.EvRgcMaxRunT, perr = time.ParseDuration(*evRgcMaxRunS)
		if perr != nil {
			e := fmt.Errorf("invalid evr_gc_max_run_time: %s: %v",
				*evRgcMaxRunS, perr)
			errs++
			return cfg, e
		}
	}
	return cfg, nil
}

func CfgCheck(cfg *Config) error {
	if len(cfg.PCAPs) == 0 && len(cfg.BPF) == 0 {
		return fmt.Errorf("at least one pcap file or a bpf expression required")
	}
	return nil
}
