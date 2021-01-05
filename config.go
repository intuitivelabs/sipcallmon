// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipcallmon

import (
	"flag"
	"fmt"
	"time"
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

	// call tracing options
	RegDelta uint `config:"reg_exp_delta"` // seconds
	// contact matching options
	ContactIgnorePort bool `config:"contact_ignore_port"`

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
}

var DefaultConfig = Config{
	ReplayMinDelay:    250 * time.Millisecond,
	ReplayMaxDelay:    0,
	TCPGcInt:          30 * time.Second,
	TCPReorderTo:      60 * time.Second,
	TCPConnTo:         3600 * time.Second,
	MaxBlockedTo:      1 * time.Second,
	EvBufferSz:        10240,
	RegDelta:          30, // seconds
	ContactIgnorePort: false,
	EncryptIPs:        false,
	EncryptURIs:       false,
	EncryptCallIDs:    false,
}

// FromOsArgs intializes and returns a config from cmd line args and
// passed default config (c).
func CfgFromOSArgs(c *Config) (Config, error) {
	var cfg Config

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
	}
	return cfg, nil
}

func CfgCheck(cfg *Config) error {
	if len(cfg.PCAPs) == 0 && len(cfg.BPF) == 0 {
		return fmt.Errorf("at least one pcap file or a bpf expression required")
	}
	if (cfg.EncryptIPs || cfg.EncryptURIs || cfg.EncryptCallIDs) &&
		(len(cfg.EncryptionPassphrase) == 0 || len(cfg.EncryptionKey) == 0) {
		return fmt.Errorf("Anonymization required and no encryption passphrase/key provided")
	}
	return nil
}
