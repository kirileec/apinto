package main

import (
	"github.com/eolinker/eosc/log"
	"os"
)

func InitCLILog() {
	formatter := &log.LineFormatter{
		TimestampFormat:  "2006-01-02 15:04:05",
		CallerPrettyfier: nil,
	}
	log.SetLevel(log.DebugLevel)
	transport := log.NewTransport(os.Stdout, log.DebugLevel)
	transport.SetFormatter(formatter)
	log.Reset(transport)
}
