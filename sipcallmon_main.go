package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const version = "6.4"

var RunningCfg *Config

func DBG(f string, a ...interface{}) {
	//fmt.Printf("DBG: "+f, a...)
}
func Run(cfg *Config) {
	var wg *sync.WaitGroup

	// save actual config for global ref.
	RunningCfg = cfg

	StartTS = time.Now()

	// ...

	// start web sever
	if cfg.HTTPport != 0 {
		wg = &sync.WaitGroup{}
		if err := HTTPServerRun(cfg.HTTPaddr, cfg.HTTPport, wg); err != nil {
			fmt.Printf("starting web server error: %s\n", err)
			os.Exit(-1)
		}
	}

	if len(cfg.PCAPs) > 0 {
		/*
			for i := 0; i < flag.NArg(); i++ {
				processPCAP(flag.Arg(i), &cfg)
			}
		*/
		for _, fn := range strings.Split(cfg.PCAPs, " ") {
			processPCAP(fn, cfg)
		}
	} else {
		//processLive(cfg.Iface, strings.Join(flag.Args(), " "), &cfg)
		processLive(cfg.Iface, cfg.BPF, cfg)
	}
	// print stats
	printStats(os.Stdout)
	//printStatsRaw(os.Stdout)
	if cfg.RunForever && wg != nil {
		wg.Wait()
	}
}
