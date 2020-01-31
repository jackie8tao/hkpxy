package ssr

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
	val, err := spt.EvpBytes2Key(key, c.keyLen)
	if err != nil {
		return err
	}
	c.key = val
	return nil
}

func (c *aesCfb) Encrypt(val []byte) (ret []byte, err error) {
	blk, err := aes.NewCipher(c.key)
	if err != nil {
		return
	}

	var iv []byte
	if c.enc == nil {
		iv, err = spt.IV(c.ivLen)
		if err != nil {
			return
		}
		if c.iv == nil {
			c.iv = iv
		}
		c.enc = cipher.NewCFBEncrypter(blk, iv)
	}

	ret = make([]byte, len(val)+len(iv))
	if iv != nil {
		copy(ret, iv)
	}
	c.enc.XORKeyStream(ret[len(iv):], val)
	return
}

func (c *aesCfb) Decrypt(val []byte) (ret []byte, err error) {
	blk, err := aes.NewCipher(c.key)
	if err != nil {
		return
	}

	if c.dec == nil {
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

func (c *aesCfb) Clone() iCipher {
	return &aesCfb{
		key:    c.key,
		keyLen: c.keyLen,
		ivLen:  c.ivLen,
	}
}

func (c *aesCfb) KeyLen() int {
	return c.keyLen
}

func (c *aesCfb) IvLen() int {
	return c.ivLen
}
