package ssr

import (
	"github.com/jackie8tao/hkpxy/ssr/crypt"
	"net"
)

type Conn struct {
	net.Conn
	crypt.ICipher
	readBuf  []byte
	writeBuf []byte
}

func NewConn(c net.Conn, m crypt.ICipher) *Conn {
	return &Conn{
		Conn:     c,
		ICipher:  m,
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
	buf := make([]byte, len(b))
	n, err = c.Conn.Read(buf)
	if err != nil {
		return
	}
	if n > 0 {
		var ret []byte
		ret, err = c.ICipher.Decrypt(buf[:n])
		if len(ret) > 0 {
			copy(b, ret)
		}
		n = len(ret)
	}
	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	var buf []byte
	buf, err = c.ICipher.Encrypt(b)
	if err != nil {
		return
	}
	n, err = c.Conn.Write(buf)
	return
}
