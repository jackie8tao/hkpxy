package main

import (
	"log"
	"os"
	"os/signal"

	"github.com/jackie8tao/hkpxy/ssr"
	"github.com/jackie8tao/hkpxy/ssr/cfg"
)

func main() {
	c := cfg.Config{
		Local: cfg.Addr{
			Host: "127.0.0.1",
			Port: 1081,
		},
	}

	srv := ssr.NewServer(c)
	if err := srv.Run(); err != nil {
		log.Fatalln(err)
	}

	sig := make(chan os.Signal)
	signal.Notify(sig, os.Interrupt)
	<-sig
}
