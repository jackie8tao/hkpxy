package ssr

import (
	"io"
	"net"

	"github.com/jackie8tao/hkpxy/ssr/spt"
)

type Conn struct {
	net.Conn
	Cryptor
	readBuf  []byte
	writeBuf []byte
}

func NewConn(c net.Conn, m Cryptor) *Conn {
	return &Conn{
		Conn:     c,
		Cryptor:  m,
		readBuf:  make([]byte, BufSize),
		writeBuf: make([]byte, BufSize),
	}
}

func DialRemote(addr, method, password string) (c *Conn, err error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return
	}
	cipher, err := NewCipher(method, password)
	if err != nil {
		return
	}
	c = NewConn(conn, cipher)
	return
}

func (c *Conn) Read(b []byte) (n int, err error) {
	var (
		buf []byte
		sz  int
	)

	iv := make([]byte, c.Cryptor.IVLen())
	n, err = io.ReadFull(c.Conn, iv)
	if err != nil {
		return
	}

	s, err := c.Cryptor.NewDec(iv)
	if err != nil {
		return
	}

	sz = len(b)
	if sz > BufSize {
		buf = make([]byte, sz)
	} else {
		buf = c.readBuf[:sz]
	}

	n, err = c.Conn.Read(buf)
	if n > 0 {
		s.XORKeyStream(b[:n], buf[:n])
	}
	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	var (
		buf []byte
		sz  int
	)

	iv, err := spt.IV(c.Cryptor.IVLen())
	if err != nil {
		return
	}
	s, err := c.Cryptor.NewEnc(iv)
	if err != nil {
		return
	}

	sz = len(b) + len(iv)
	if sz > BufSize {
		buf = make([]byte, sz)
	} else {
		buf = c.writeBuf[:sz]
	}
	copy(buf, iv)
	s.XORKeyStream(buf[len(iv):], b)
	n, err = c.Conn.Write(b)
	return
}
