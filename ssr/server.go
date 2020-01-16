package ssr

import (
	"context"
	"net"

	"github.com/jackie8tao/hkpxy/ssr/cfg"
)

type Server struct {
	Debug bool

	cfg cfg.Config
	ctx context.Context
}

//NewServer create new socks5 struct
func NewServer(cfg cfg.Config) *Server {
	ctx, _ := context.WithCancel(context.Background())
	return &Server{
		cfg: cfg,
		ctx: ctx,
	}
}

//Run start sock5 server and listen http
func (s *Server) Run() error {
	var err error
	if err = s.doSock5(); err != nil {
		return err
	}

	return nil
}

//handle socks5 packet, establish sock5 connection
func (s *Server) doSock5() error {
	var (
		addr *net.TCPAddr
		lis  *net.TCPListener
		err  error
	)

	addr, err = net.ResolveTCPAddr("tcp", s.cfg.LocalVal())
	if err != nil {
		return err
	}

	lis, err = net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}

	go func(ctx context.Context) {
		for {
			conn, err := lis.Accept()
			if err != nil {
				continue
			}

			select {
			case <-ctx.Done():
				return
			default:
			}

			go sock5Handler(conn)
		}
	}(s.ctx)

	return nil
}
