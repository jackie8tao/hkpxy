package ssr

import (
	"net"
	"sync"

	"github.com/jackie8tao/hkpxy/ssr/crypt"
	"github.com/jackie8tao/hkpxy/ssr/obfs"
	"github.com/jackie8tao/hkpxy/ssr/prtl"
	"github.com/jackie8tao/hkpxy/ssr/spt"
	log "github.com/sirupsen/logrus"
)

type SSConn struct {
	net.Conn
	crypt.ICipher
}

type SSRConn struct {
	net.Conn
	sync.RWMutex
	crypt.ICipher
	obfs.IObfs
	prtl.IProtocol
	left          []byte
	readBuf       []byte
	writeBuf      []byte
	lastReadError error
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
	conn, err := net.Dial("tcp", "hk-09.apnicpro.cn:995")
	if err != nil {
		return
	}
	cr, err := crypt.NewCipher("aes-256-ctr", "&Xj781*hO42a")
	if err != nil {
		return
	}

	obfsObj := obfs.NewObfs("tls1.2_ticket_auth")
	obfsObj.SetServerInfo(&spt.ServerInfoForObfs{
		Host:   "hk-09.apnicpro.cn",
		Port:   995,
		TcpMss: 1460,
		Param:  "f73dd9480.microsoft.com",
	})
	ptrlObj := prtl.NewProtocol("auth_aes128_sha1")
	ptrlObj.SetServerInfo(&spt.ServerInfoForObfs{
		Host:   "hk-09.apnicpro.cn",
		Port:   995,
		TcpMss: 1460,
		Param:  "38780:ShaHf4",
	})

	c = &SSRConn{
		Conn:      conn,
		ICipher:   cr,
		IObfs:     obfsObj,
		IProtocol: ptrlObj,
		left:      make([]byte, BufSize),
		readBuf:   make([]byte, BufSize),
		writeBuf:  make([]byte, BufSize),
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

func (c *SSRConn) doRead() (err error) {
	if c.lastReadError != nil {
		return c.lastReadError
	}
	c.Lock()
	defer c.Unlock()
	inData := c.readBuf
	var n int
	n, c.lastReadError = c.Conn.Read(inData)
	if n > 0 {
		var decodedData []byte
		var needSendBack bool
		decodedData, needSendBack, err = c.IObfs.Decode(inData[:n])
		if err != nil {
			return
		}

		if needSendBack {
			log.Debug("do send back")
			//buf := c.IObfs.Encode(make([]byte, 0))
			//c.Conn.Write(buf)
			_, _ = c.Write(make([]byte, 0))
			return nil
		}

		if decodedDataLen := len(decodedData); decodedDataLen > 0 {
			//c.decrypt(b[0:n], inData[0:n])
			var buf []byte
			buf, err = c.ICipher.Decrypt(decodedData)
			if err != nil {
				return
			}
			decodedDataLen = len(buf)

			var postDecryptedData []byte
			postDecryptedData, err = c.IProtocol.PostDecrypt(buf)
			if err != nil {
				return
			}
			postDecryptedDataLen := len(postDecryptedData)
			if postDecryptedDataLen > 0 {
				b := make([]byte, len(c.left)+postDecryptedDataLen)
				copy(b, c.left)
				copy(b[len(c.left):], postDecryptedData)
				c.left = b
				return
			}
		}
	}
	return
}

func (c *SSRConn) Read(b []byte) (n int, err error) {
	c.RLock()
	leftLength := len(c.left)
	c.RUnlock()
	if leftLength == 0 {
		if err = c.doRead(); err != nil {
			return 0, err
		}
	}
	if c.lastReadError != nil {
		defer func() {
			go c.doRead()
		}()
	}

	if leftLength := len(c.left); leftLength > 0 {
		maxLength := len(b)
		if leftLength > maxLength {
			c.Lock()
			copy(b, c.left[:maxLength])
			c.left = c.left[maxLength:]
			c.Unlock()
			return maxLength, nil
		}

		c.Lock()
		copy(b, c.left)
		c.left = nil
		c.Unlock()
		return leftLength, c.lastReadError
	}
	return 0, c.lastReadError
}

func (c *SSRConn) preWrite(b []byte) (outData []byte, err error) {
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

	var preEncryptedData []byte
	preEncryptedData, err = c.IProtocol.PreEncrypt(b)
	if err != nil {
		return
	}
	//c.encrypt(cipherData[len(iv):], b)
	var encryptedData []byte
	//! \attention here the expected output buffer length MUST be accurate, it is preEncryptedDataLen now!
	encryptedData, err = c.ICipher.Encrypt(preEncryptedData)
	if err != nil {
		return
	}

	//common.Info("len(b)=", len(b), ", b:", b,
	//	", pre encrypted data length:", preEncryptedDataLen,
	//	", pre encrypted data:", preEncryptedData,
	//	", encrypted data length:", preEncryptedDataLen)

	return c.IObfs.Encode(encryptedData)
}

func (c *SSRConn) Write(b []byte) (n int, err error) {
	outData, err := c.preWrite(b)
	if err == nil {
		n, err = c.Conn.Write(outData)
	}
	return
}
