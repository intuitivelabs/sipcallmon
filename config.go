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
	"github.com/intuitivelabs/slog"
)

type Config struct {
	Verbose        bool          `config:"verbose"`
	LogLev         int64         `config:"log_level"`
	LogOpt         uint64        `config:"log_opt"`
	ParseLogLev    int64         `config:"parse_log_level"`
	ParseLogOpt    uint64        `config:"parse_log_opt"`
	DbgCalltr      uint64        `config:"debug_calltr"`
	PCAPs          string        `config:"pcap"`
	PCAPloop       uint64        `config:"pcap_loop"`
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
	CallStMax      uint          `config:"calls_max_entries"`
	CallStMaxMem   uint64        `config:"calls_max_mem"`
	RegsMax        uint          `config:"regs_max_entries"`
	RegsMaxMem     uint64        `config:"regs_max_mem"`
	EvBufferSz     int           `config:"event_buffer_size"`
	EvTblst        []string      `config:"event_types_blst"`
	// maximum entries in the rate blacklist table.
	EvRblstMax uint `config:"evr_max_entries"`
	// ev rate blacklist max values for each rate
	EvRblstMaxVals [calltr.NEvRates]float64 `config:"evr_limits"`
	// ev rate blacklist time intervals for each rate
	EvRblstIntvls [calltr.NEvRates]time.Duration `config:"evr_intervals"`
	// ev rate blacklist re-repeat report event minimum
	EvRConseqRmin uint64 `config:"evr_conseq_report_min"`
	// ev rate blacklist re-repeat report event maximum
	EvRConseqRmax uint64 `config:"evr_conseq_report_max"`

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
	EvRgcTarget uint64 `config:"evr_gc_target"`

	// call tracing options
	RegDelta uint `config:"reg_exp_delta"` // seconds
	// contact matching options
	ContactIgnorePort bool `config:"contact_ignore_port"`

	// periodic statistic events (sipcmbeat only)
	StatsInterval time.Duration `config:"stats_interval"`

	// anonymization/encryption options
	// are the IPs encrypted?
	EncryptIPs bool `config:"encrypt_ip_addresses"`
	// are the URIs encrypted?
	EncryptURIs bool `config:"encrypt_uris"`
	// are the CallIDs encrypted?
	EncryptCallIDs bool `config:"encrypt_call_ids"`

	// encryption key is either generated from a configured passphrase...
	EncryptionPassphrase string `config:"encryption_passphrase"`
	// ... or directly configured
	EncryptionKey string `config:"encryption_key"`
	// encryption key validation salt
	EncryptionValSalt string `config:"encryption_salt"`
}

var defaultConfigVals = Config{
	LogLev:            int64(slog.LINFO),
	LogOpt:            uint64(slog.LlocInfoS),
	ParseLogLev:       int64(slog.LNOTICE),
	ParseLogOpt:       uint64(slog.LOptNone),
	DbgCalltr:         uint64(calltr.DefaultConfig.Dbg),
	ReplayMinDelay:    250 * time.Millisecond,
	ReplayMaxDelay:    0,
	TCPGcInt:          30 * time.Second,
	TCPReorderTo:      60 * time.Second,
	TCPConnTo:         3600 * time.Second,
	MaxBlockedTo:      1 * time.Second,
	EvBufferSz:        10240,
	EvRblstMax:        1024 * 1024,
	EvRConseqRmin:     100,
	EvRConseqRmax:     10000,
	EvRgcInterval:     10 * time.Second,
	EvRgcOldAge:       300 * time.Second,
	EvRgcMaxRunT:      1 * time.Second,
	EvRgcTarget:       10, // 10? entries
	RegDelta:          30, // seconds
	ContactIgnorePort: false,
	StatsInterval:     5 * time.Minute,
	EncryptIPs:        false,
	EncryptURIs:       false,
	EncryptCallIDs:    false,
}

func (cfg Config) UseIPAnonymization() bool {
	return cfg.EncryptIPs
}

func (cfg Config) UseURIAnonymization() bool {
	return cfg.EncryptURIs
}

func (cfg Config) UseCallIDAnonymization() bool {
	return cfg.EncryptCallIDs
}

func (cfg Config) UseAnonymization() bool {
	return cfg.UseIPAnonymization() ||
		cfg.UseURIAnonymization() ||
		cfg.UseCallIDAnonymization()
}

var DefaultMaxRates = calltr.EvRateMaxes{
	{20, time.Second}, // max 20 evs per s
	{240, time.Minute},
	{3600, time.Hour},
}

var defaultEvTblst = ""

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
	var evTblst string
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
	flag.Int64Var(&cfg.LogLev, "log_level", c.LogLev, "log level")
	flag.Uint64Var(&cfg.LogOpt, "log_opt", c.LogOpt, "log format options")
	flag.Int64Var(&cfg.ParseLogLev, "parse_log_level", c.ParseLogLev,
		"log level for capturing and parsing")
	flag.Uint64Var(&cfg.ParseLogOpt, "parse_log_opt", c.ParseLogOpt,
		"log format options for parsing")
	flag.Uint64Var(&cfg.DbgCalltr, "debug_calltr", c.DbgCalltr,
		"debugging flags for call tracking")
	flag.StringVar(&cfg.PCAPs, "pcap", c.PCAPs, "read packets from pcap files")
	flag.Uint64Var(&cfg.PCAPloop, "pcap_loop", c.PCAPloop,
		"loop through pcap files multiple times")
	flag.BoolVar(&cfg.Replay, "replay", c.Replay, "replay packets from pcap "+
		"keeping recorded delays between packets")
	replMinDelayS := flag.String("replay_min_delay", c.ReplayMaxDelay.String(),
		"minimum delay when replaying pcaps")
	replMaxDelayS := flag.String("replay_max_delay", c.ReplayMaxDelay.String(),
		"maximum delay when replaying pcaps")
	flag.Float64Var(&cfg.ReplayScale, "replay_scale", c.ReplayScale,
		"scale factor for inter packet delay intervals")
	flag.BoolVar(&cfg.RunForever, "run_forever", c.RunForever,
		"keep web server running")

	flag.StringVar(&cfg.Iface, "iface", c.Iface,
		"interface to capture packets from")
	flag.StringVar(&cfg.BPF, "bpf", c.BPF, "berkley packet filter for capture")

	flag.IntVar(&cfg.HTTPport, "http_port", c.HTTPport,
		"port for the internal http server, 0 == disable")
	flag.StringVar(&cfg.HTTPaddr, "http_addr", c.HTTPaddr,
		"listen address for the internal http server")

	tcpGCIntS := flag.String("tcp_gc_int", c.TCPGcInt.String(),
		"tcp connections garbage collection interval")
	tcpReorderToS := flag.String("tcp_reorder_timeout", c.TCPReorderTo.String(),
		"tcp reorder timeout")
	tcpConnToS := flag.String("tcp_connection_timeout", c.TCPConnTo.String(),
		"tcp connection timeout")
	maxBlockedToS := flag.String("max_blocked_timeout",
		c.MaxBlockedTo.String(), "maximum blocked timeout")
	flag.UintVar(&cfg.CallStMax, "calls_max_entries", c.CallStMax,
		"maximum tracked calls (0 for unlimited)")
	flag.Uint64Var(&cfg.CallStMaxMem, "calls_max_mem", c.CallStMaxMem,
		"maximum memory for keeping call state (0 for unlimited)")
	flag.UintVar(&cfg.RegsMax, "regs_max_entries", c.RegsMax,
		"maximum tracked register bindings (0 for unlimited)")
	flag.Uint64Var(&cfg.RegsMaxMem, "regs_max_mem", c.RegsMaxMem,
		"maximum memory for register bindings (0 for unlimited)")
	flag.IntVar(&cfg.EvBufferSz, "event_buffer_size", c.EvBufferSz,
		"how many events will be buffered")
	flag.StringVar(&evTblst, "event_types_blst", defaultEvTblst,
		"list of event types that should be blacklisted,"+
			" comma or space separated")
	flag.UintVar(&cfg.EvRblstMax, "evr_max_entries", c.EvRblstMax,
		"maximum tracked event rates")
	flag.StringVar(&evRmaxVals, "evr_limits", defaultEvRmaxVals,
		"event rate max values list, comma or space separated")
	flag.StringVar(&evRIntvls, "evr_intervals", defaultEvRIntvls,
		"event rate intervals list, comma or space separated")
	flag.Uint64Var(&cfg.EvRConseqRmin, "evr_conseq_report_min",
		c.EvRConseqRmin,
		"report blacklisted events only if the number is a multiple"+
			" of this value and 2^k and < evr_conseq_report_max")
	flag.Uint64Var(&cfg.EvRConseqRmax, "evr_conseq_report_max",
		c.EvRConseqRmax,
		"report blacklisted events only if the number is a multiple"+
			" of this value (use 0 to disable)")

	evRgcIntervalS := flag.String("evr_gc_interval",
		c.EvRgcInterval.String(), "event rate periodic GC interval")
	evRgcOldAgeS := flag.String("evr_gc_old_age",
		c.EvRgcOldAge.String(),
		"event rate old age: non-blst. entries idle for more then this value"+
			" will be GCed")
	evRgcMaxRunS := flag.String("evr_gc_max_run_time",
		c.EvRgcMaxRunT.String(), "maximum runtime for each periodic GC run")
	flag.Uint64Var(&cfg.EvRgcTarget, "evr_gc_target", c.EvRgcTarget,
		"event rate periodic GC target: GC will stop if the number of"+
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
			if r == rune(',') || r == rune('|') || unicode.IsSpace(r) ||
				r == rune('[') || r == rune(']') {
				return true
			}
			return false
		}
		cfg.EvTblst = c.EvTblst
		blst_types := strings.FieldsFunc(evTblst, checkSep)
		blst_vals := make([]string, 0, 10)
		for _, t := range blst_types {
			if len(t) == 0 {
				continue
			}
			blst_vals = append(blst_vals, t)
		}
		if len(blst_vals) > 0 {
			cfg.EvTblst = blst_vals
		}

		cfg.EvRblstMaxVals = c.EvRblstMaxVals
		rate_vals := strings.FieldsFunc(evRmaxVals, checkSep)
		k := 0
		for _, s := range rate_vals {
			if len(s) == 0 {
				continue
			}
			if k < len(cfg.EvRblstMaxVals) {
				if v, perr := strconv.ParseFloat(s, 64); perr == nil {
					cfg.EvRblstMaxVals[k] = v
				} else {
					e := fmt.Errorf("invalid rate max[%d]: %q in %q",
						k, s, evRmaxVals)
					errs++
					return cfg, e
				}
			} else {
				e := fmt.Errorf("too many rate max values: %d (max %d) in %q",
					k, len(cfg.EvRblstMaxVals), evRmaxVals)
				errs++
				return cfg, e
			}
			k++
		}
		cfg.EvRblstIntvls = c.EvRblstIntvls
		rate_intvls := strings.FieldsFunc(evRIntvls, checkSep)
		k = 0
		for _, s := range rate_intvls {
			if len(s) == 0 {
				continue
			}
			if k < len(cfg.EvRblstIntvls) {
				if v, perr := time.ParseDuration(s); perr == nil {
					cfg.EvRblstIntvls[k] = v
				} else {
					e := fmt.Errorf("invalid rate interval[%d]: %q in %q",
						k, s, evRIntvls)
					errs++
					return cfg, e
				}
			} else {
				e := fmt.Errorf("too many rate interval values:"+
					" %d (max %d) in %q",
					k, len(cfg.EvRblstIntvls), evRIntvls)
				errs++
				return cfg, e
			}
			k++
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

func parseEvType(t string) (calltr.EventType, error) {
	for i := calltr.EvNone + 1; i < calltr.EvBad; i++ {
		if strings.EqualFold(t, i.String()) {
			return i, nil
		}
	}
	return calltr.EvBad, fmt.Errorf("invalid event %q", t)
}

func CfgCheck(cfg *Config) error {
	if len(cfg.PCAPs) == 0 && len(cfg.BPF) == 0 {
		return fmt.Errorf("at least one pcap file or a bpf expression required")
	}
	if cfg.UseAnonymization() {
		if len(cfg.EncryptionPassphrase) == 0 &&
			len(cfg.EncryptionKey) == 0 {
			return fmt.Errorf("Anonymization required and neither encryption passphrase nor key provided")
		}
		if len(cfg.EncryptionPassphrase) != 0 &&
			len(cfg.EncryptionKey) != 0 {
			return fmt.Errorf("Anonymization required and both encryption passphrase and key provided")
		}
	}
	for _, t := range cfg.EvTblst {
		if len(t) > 0 {
			if _, perr := parseEvType(t); perr != nil {
				return fmt.Errorf("invalid event type in even_type_blst: %q",
					t)
			}
		}
	}
	return nil
}
