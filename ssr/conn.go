package ssr

import (
	"net"

	"github.com/jackie8tao/hkpxy/ssr/crypt"
)

type Conn struct {
	net.Conn
	crypt.Cryptor
	readBuf  []byte
	writeBuf []byte
}

func NewConn(c net.Conn, m crypt.Cryptor) *Conn {
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
	cipher, err := crypt.NewCipher(method, password)
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

	sz = len(b)
	if sz > BufSize {
		buf = make([]byte, sz)
	} else {
		buf = c.readBuf[:sz]
	}

	n, err = c.Conn.Read(buf)
	if n > 0 {
		c.Decrypt(b[:n], buf[:n])
	}
	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	var (
		buf []byte
		sz  int
	)

	sz = len(b) + len(c.Iv())
	if sz > BufSize {
		buf = make([]byte, sz)
	} else {
		buf = c.writeBuf[:sz]
	}

	if c.Iv() != nil {
		copy(buf, c.Iv())
	}

	c.Encrypt(buf[len(c.Iv()):], b)
	n, err = c.Conn.Write(b)
	return
}
