package ssr

import (
	"net"

	"github.com/jackie8tao/hkpxy/ssr/crypt"
	"github.com/jackie8tao/hkpxy/ssr/obfs"
	"github.com/jackie8tao/hkpxy/ssr/prtl"
	"github.com/jackie8tao/hkpxy/ssr/spt"
)

type SSConn struct {
	net.Conn
	crypt.ICipher
}

type SSRConn struct {
	net.Conn
	crypt.ICipher
	obfs.IObfs
	prtl.IProtocol
}

func DialSS(addr, method, password string) (c *SSConn, err error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return
	}
	cr, err := crypt.NewCipher(method, password)
	if err != nil {
		return
	}
	c = &SSConn{Conn: conn, ICipher: cr}
	return
}

func DialSSR(addr, method, password string) (c *SSRConn, err error) {
	conn, err := net.Dial("tcp", "hk-05.apnicpro.cn:80")
	if err != nil {
		return
	}
	cr, err := crypt.NewCipher("aes-256-ctr", "WjR6I1Y1JCU2OSV5MlZ5JGRi")
	if err != nil {
		return
	}

	obfsObj := obfs.NewObfs("tls1.2_ticket_auth")
	obfsObj.SetServerInfo(&spt.ServerInfoForObfs{
		Host:   "hk-05.apnicpro.cn",
		Port:   80,
		TcpMss: 1460,
		Param:  "cDEteGcuYnl0ZWNkbi5jbg",
	})
	ptrlObj := prtl.NewProtocol("auth_aes128_sha1")
	ptrlObj.SetServerInfo(&spt.ServerInfoForObfs{
		Host:   "hk-05.apnicpro.cn",
		Port:   80,
		TcpMss: 1460,
		Param:  "Mzg3ODA6U2hhSGY0",
	})

	c = &SSRConn{
		Conn:      conn,
		ICipher:   cr,
		IObfs:     obfsObj,
		IProtocol: ptrlObj,
	}
	return
}

func (c *SSConn) Read(b []byte) (n int, err error) {
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

func (c *SSConn) Write(b []byte) (n int, err error) {
	var buf []byte
	buf, err = c.ICipher.Encrypt(b)
	if err != nil {
		return
	}
	n, err = c.Conn.Write(buf)
	return
}

func (c *SSRConn) Read(b []byte) (n int, err error) {
	obfsData := make([]byte, len(b))
	n, err = c.Conn.Read(obfsData)
	if err != nil {
		return
	}
	if n > 0 {
		var (
			sendBack   bool
			cipherData []byte
		)
		cipherData, sendBack, err = c.IObfs.Decode(obfsData[:n])
		if err != nil {
			return
		}
		if sendBack {
			_, _ = c.Write(make([]byte, 0))
			return
		}

		if len(cipherData) > 0 {
			var prtlData []byte
			prtlData, err = c.ICipher.Decrypt(cipherData)
			if err != nil {
				return
			}

			var rawData []byte
			rawData, err = c.IProtocol.PostDecrypt(prtlData)
			if err != nil {
				return
			}

			if len(rawData) > 0 {
				copy(b, rawData)
				n = len(rawData)
			}
		}
	}
	return
}

func (c *SSRConn) initObfs(b []byte) {
	obfsInfo := c.IObfs.GetServerInfo()
	obfsInfo.SetHeadLen(b, 30)
	obfsInfo.IV = c.IV()
	obfsInfo.IVLen = len(obfsInfo.IV)
	obfsInfo.Key = c.Key()
	obfsInfo.KeyLen = len(obfsInfo.Key)
	c.IObfs.SetServerInfo(obfsInfo)

	ptrlInfo := c.IProtocol.GetServerInfo()
	ptrlInfo.SetHeadLen(b, 30)
	ptrlInfo.IV = c.IV()
	ptrlInfo.IVLen = len(ptrlInfo.IV)
	ptrlInfo.Key = c.Key()
	ptrlInfo.KeyLen = len(ptrlInfo.Key)
	c.IProtocol.SetServerInfo(ptrlInfo)
}

func (c *SSRConn) Write(b []byte) (n int, err error) {
	c.initObfs(b)
	var prtlData []byte
	prtlData, err = c.IProtocol.PreEncrypt(b)
	if err != nil {
		return
	}
	var cipherData []byte
	cipherData, err = c.ICipher.Encrypt(prtlData)
	if err != nil {
		return
	}

	var obfsData []byte
	obfsData, err = c.IObfs.Encode(cipherData)
	if err != nil {
		return
	}

	n, err = c.Conn.Write(obfsData)
	return
}
