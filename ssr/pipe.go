package ssr

import (
	"log"
	"net"
)

type Pipe struct {
	Lcl net.Conn
	Rmt net.Conn
}

func (p *Pipe) Run() {
	transfer(p.Lcl, p.Rmt)    /*send*/
	go transfer(p.Rmt, p.Lcl) /*recv*/
}

func transfer(src, dst net.Conn) {
	defer func() {
		_ = src.Close()
		_ = dst.Close()
	}()

	buf := make([]byte, BufSize)
	for {
		n, err := src.Read(buf)
		if err != nil {
			log.Println(err)
			return
		}
		if n > 0 {
			log.Printf("%x\n", buf[:n])
			_, err := dst.Write(buf[0:n])
			if err != nil {
				log.Println(err)
				return
			}
		}
	}
}
