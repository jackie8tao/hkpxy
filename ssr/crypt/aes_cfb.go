package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"

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

func (c *aesCfb) setIv(iv ...string) {
	if len(iv) > 0 {
		c.iv = []byte(iv[0])
		return
	}

	c.iv = make([]byte, c.ivLen)
	_, err := io.ReadFull(rand.Reader, c.iv)
	if err != nil {
		log.Fatalln(err)
	}
}

func (c *aesCfb) setKey(key string) {
	val, err := spt.EvpBytes2Key(key, c.keyLen)
	if err != nil {
		log.Fatalln(err)
	}
	c.key = val
}

func (c *aesCfb) Init(key string, iv ...string) {
	c.setKey(key)
	c.setIv(iv...)
}

func (c *aesCfb) Encrypt(dst, src []byte) {
	blk, err := aes.NewCipher(c.key)
	if err != nil {
		log.Fatalln(err)
	}
	c.enc = cipher.NewCFBEncrypter(blk, c.iv)
	c.enc.XORKeyStream(dst, src)
}

func (c *aesCfb) Decrypt(dst, src []byte) {
	blk, err := aes.NewCipher(c.key)
	if err != nil {
		log.Fatalln(err)
	}
	c.dec = cipher.NewCFBDecrypter(blk, c.iv)
	c.dec.XORKeyStream(dst, src)
}

func (c *aesCfb) Iv() []byte {
	return c.iv
}
