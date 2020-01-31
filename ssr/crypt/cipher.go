package crypt

type Cryptor interface {
	Init(key string, iv ...string)
	Iv() []byte
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)
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
