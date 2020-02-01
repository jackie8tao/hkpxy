package ss

import (
	"io"
	"net"

	log "github.com/sirupsen/logrus"
)

type Pipe struct {
	Lcl net.Conn
	Rmt net.Conn
}

func (p *Pipe) Run() {
	defer func() {
		_ = p.Rmt.Close()
		_ = p.Lcl.Close()
	}()
	go transfer(p.Lcl, p.Rmt) /*send*/
	transfer(p.Rmt, p.Lcl)    /*recv*/
}

func transfer(src, dst net.Conn) {
	buf := make([]byte, BufSize)
	for {
		n, err := src.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Println(err)
			}
			return
		}
		if n > 0 {
			_, err := dst.Write(buf[0:n])
			if err != nil {
				log.Println(err)
				return
			}
		}
	}
}
