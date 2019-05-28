package sipcallmon

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

// ugly temporary hack
var waitgrp *sync.WaitGroup
var stopProcessing = false // if set to 1, will stop

func Stop() {
	stopProcessing = true
	if waitgrp != nil {
		waitgrp.Add(-1)
	}
}

func Run(cfg *Config) {

	// save actual config for global ref.
	RunningCfg = cfg

	StartTS = time.Now()

	// ...

	// start web sever
	if cfg.HTTPport != 0 {
		waitgrp = &sync.WaitGroup{}
		if err := HTTPServerRun(cfg.HTTPaddr, cfg.HTTPport, waitgrp); err != nil {
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
	if cfg.RunForever && waitgrp != nil {
		waitgrp.Wait()
	}
}
