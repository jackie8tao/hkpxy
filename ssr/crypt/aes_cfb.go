package crypt

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/jackie8tao/hkpxy/ssr/spt"
)

type aesCfb struct {
	key    []byte
	keyLen int
	iv     []byte
	ivLen  int
	dec    cipher.Stream
	enc    cipher.Stream
}

func (c *aesCfb) Setup(key string) error {
	c.key = spt.EVPBytes2Key(key, c.keyLen)
	iv, err := spt.IV(c.ivLen)
	if err != nil {
		return err
	}
	c.iv = iv
	return nil
}

func (c *aesCfb) Encrypt(val []byte) (ret []byte, err error) {
	var iv []byte
	if c.enc == nil {
		var blk cipher.Block
		blk, err = aes.NewCipher(c.key)
		if err != nil {
			return
		}
		iv = c.iv
		c.enc = cipher.NewCFBEncrypter(blk, c.iv)
	}
	ret = make([]byte, len(val)+len(iv))
	if iv != nil {
		copy(ret, iv)
	}
	c.enc.XORKeyStream(ret[len(iv):], val)
	return
}

func (c *aesCfb) Decrypt(val []byte) (ret []byte, err error) {
	if c.dec == nil {
		var blk cipher.Block
		blk, err = aes.NewCipher(c.key)
		if err != nil {
			return
		}
		var iv []byte
		iv, val = val[:c.ivLen], val[c.ivLen:]
		if c.iv == nil {
			c.iv = iv
		}
		c.dec = cipher.NewCFBDecrypter(blk, iv)
	}

	ret = make([]byte, len(val))
	c.dec.XORKeyStream(ret, val)
	return
}

func (c *aesCfb) Clone() ICipher {
	return &aesCfb{
		key:    c.key,
		keyLen: c.keyLen,
		ivLen:  c.ivLen,
	}
}

func (c *aesCfb) Key() []byte {
	ret := make([]byte, c.keyLen)
	copy(ret, c.key)
	return ret
}

func (c *aesCfb) IV() []byte {
	ret := make([]byte, c.ivLen)
	copy(ret, c.iv)
	return ret
}
