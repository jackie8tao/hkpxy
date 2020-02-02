package main

import (
	"flag"
	"io"
	"net"
	"os"
	"os/signal"

	"github.com/jackie8tao/hkpxy/ssr"
	"github.com/jackie8tao/hkpxy/ssr/cfg"
	log "github.com/sirupsen/logrus"
)

var _cfg *cfg.Config

func init() {
	_cfg = &cfg.Config{}
}

func main() {
	var (
		err     error
		cfgPath string
	)

	flag.StringVar(&cfgPath, "c", "", "specify config file")
	flag.StringVar(&_cfg.Remote.Host, "s", "127.0.0.1", "server address")
	flag.UintVar(&_cfg.Remote.Port, "p", 8838, "server port")
	flag.StringVar(&_cfg.Local.Host, "b", "127.0.0.1", "local address")
	flag.UintVar(&_cfg.Local.Port, "l", 1080, "local socks5 port")
	flag.StringVar(&_cfg.Method, "m", "aes-256-cfb", "encryption method, default: aes-256-cfb")
	flag.StringVar(&_cfg.Password, "k", "foobar", "password, default: foobar")
	flag.IntVar(&_cfg.Timeout, "t", 300, "timeout in seconds")

	flag.Parse()

	if cfgPath != "" {
		_cfg, err = cfg.Parse(cfgPath)
		if err != nil {
			log.Fatalln(err)
		}
	}

	go run()
	sig := make(chan os.Signal)
	signal.Notify(sig, os.Interrupt)
	<-sig
}

func run() {
	l, err := net.Listen("tcp", _cfg.LocalVal())
	if err != nil {
		log.Fatalln(err)
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println(err)
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	if err := handshake(conn); err != nil {
		log.Println(err)
		return
	}
	addr, err := request(conn)
	if err != nil {
		log.Println(err)
		return
	}
	_, err = conn.Write([]byte{
		0x05, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x08, 0x43,
	})
	if err != nil {
		log.Println(err)
	}
	rmt, err := connRemote(addr)
	if err != nil {
		log.Println(err)
		return
	}
	p := &ssr.Pipe{Lcl: conn, Rmt: rmt}
	go p.Run()
	return
}

func handshake(conn net.Conn) error {
	const (
		idVer     = 0
		idNMethod = 1
		bufSize   = 258 /*1ver + 1nmethod + 256methods*/
	)
	buf := make([]byte, bufSize)
	n, err := io.ReadAtLeast(conn, buf, idNMethod+1)
	if err != nil {
		return err
	}

	if buf[idVer] != ssr.Ss5VerVal {
		return errVer
	}

	nMethod := int(buf[idNMethod])
	msgLen := nMethod + 2
	if n > msgLen {
		return errData
	}
	if n < msgLen {
		_, err = io.ReadFull(conn, buf[n:msgLen])
		if err != nil {
			return err
		}
	}

	_, err = conn.Write([]byte{ssr.Ss5VerVal, ssr.Ss5NoAuthVal})
	if err != nil {
		return err
	}
	return nil
}

func request(conn net.Conn) (addr []byte, err error) {
	const (
		idVer     = 0
		idCmd     = 1
		idAtyp    = 3
		idIP0     = 4
		idDmLen   = 4
		idDm0     = 5
		lenIPv4   = 3 + 1 + net.IPv4len + 2 /*3(ver+cmd+rsv) + 1addrType + ipv4 + 2port*/
		lenIPv6   = 3 + 1 + net.IPv6len + 2 /*3(ver+cmd+rsv) + 1addrType + ipv6 + 2port*/
		lenDmBase = 3 + 1 + 1 + 2           /*3 + 1addrType + 1addrLen + 2port, plus addrLen*/
		bufSize   = 263                     /*3(ver+cmd+rsv) + 1addrType + 2port + 257domain*/
	)

	buf := make([]byte, bufSize)
	n, err := io.ReadAtLeast(conn, buf, idDmLen+1)
	if err != nil {
		return
	}

	if buf[idVer] != ssr.Ss5VerVal {
		err = errVer
		return
	}
	if buf[idCmd] != ssr.Ss5CmdConnect {
		err = errCmd
		return
	}

	msgLen := 0
	switch buf[idAtyp] {
	case ssr.Ss5AtypIpV4:
		msgLen = lenIPv4
	case ssr.Ss5AtypIpV6:
		msgLen = lenIPv6
	case ssr.Ss5AtypDomain:
		msgLen = int(buf[idDmLen]) + lenDmBase
	default:
		err = errAddr
		return
	}

	if n > msgLen {
		err = errData
		return
	}
	if n < msgLen {
		_, err = io.ReadFull(conn, buf[n:msgLen])
		if err != nil {
			return
		}
	}

	addr = buf[idAtyp:msgLen]
	return
}

func connRemote(addr []byte) (conn net.Conn, err error) {
	conn, err = ssr.DialSSR(
		_cfg.RemoteVal(), _cfg.Method, _cfg.Password,
	)
	if err != nil {
		return
	}
	_, err = conn.Write(addr)
	return
}
