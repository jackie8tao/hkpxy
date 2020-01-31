package ssr

import (
	"io"
	"log"
	"net"
)

type Pipe struct {
	Lcl net.Conn
	Rmt net.Conn
}

func (p *Pipe) Run() {
	sig := make(chan bool)
	go transfer(p.Lcl, p.Rmt, sig) /*send*/
	go transfer(p.Rmt, p.Lcl, sig) /*recv*/

	count := 0
	for {
		select {
		case closed := <-sig:
			if closed {
				count++
				if count >= 2 {
					p.Lcl.Close()
					p.Rmt.Close()
				}
			}
		}
	}
}

func transfer(src, dst net.Conn, sig chan bool) {
	buf := make([]byte, BufSize)
	for {
		n, err := src.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Println(err)
			}
			sig <- true
			return
		}
		if n > 0 {
			_, err := dst.Write(buf[0:n])
			if err != nil {
				log.Println(err)
				sig <- true
				return
			}
		}
	}
}
