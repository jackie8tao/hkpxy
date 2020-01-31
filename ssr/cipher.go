package ssr

import "crypto/cipher"

type Cryptor interface {
	Init(password string)
	KeyLen() int
	IVLen() int
	NewEnc(iv []byte) (cipher.Stream, error)
	NewDec(iv []byte) (cipher.Stream, error)
}

const (
	AES128CFB = "aes-128-cfb"
	AES192CFB = "aes-192-cfb"
	AES256CFB = "aes-256-cfb"
)

var _ciphers = map[string]Cryptor{
	AES128CFB: &aesCfb{keyLen: 16, ivLen: 16},
	AES192CFB: &aesCfb{keyLen: 24, ivLen: 16},
	AES256CFB: &aesCfb{keyLen: 32, ivLen: 16},
}

func NewCipher(method, password string) (c Cryptor, err error) {
	var ok bool
	c, ok = _ciphers[method]
	if !ok {
		err = errMethod
	}
	c.Init(password)
	return
}
