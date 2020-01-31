package ssr

import (
	"crypto/aes"
	"crypto/cipher"
	"log"

	"github.com/jackie8tao/hkpxy/ssr/spt"
)

type aesCfb struct {
	key    []byte
	keyLen int
	ivLen  int
}

func (c *aesCfb) Init(key string) {
	val, err := spt.EvpBytes2Key(key, c.keyLen)
	if err != nil {
		log.Fatalln(err)
	}
	c.key = val
}

func (c *aesCfb) NewEnc(iv []byte) (s cipher.Stream, err error) {
	blk, err := aes.NewCipher(c.key)
	if err != nil {
		return
	}
	s = cipher.NewCFBEncrypter(blk, iv)
	return
}

func (c *aesCfb) NewDec(iv []byte) (s cipher.Stream, err error) {
	blk, err := aes.NewCipher(c.key)
	if err != nil {
		return
	}
	s = cipher.NewCFBDecrypter(blk, iv)
	return
}

func (c *aesCfb) KeyLen() int {
	return c.keyLen
}

func (c *aesCfb) IVLen() int {
	return c.ivLen
}
