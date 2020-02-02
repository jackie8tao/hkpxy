package crypt

type ICipher interface {
	Setup(password string) error
	Decrypt(val []byte) ([]byte, error)
	Encrypt(val []byte) ([]byte, error)
	Key() []byte
	IV() []byte
	Clone() ICipher
}

const (
	AES128CFB = "aes-128-cfb"
	AES192CFB = "aes-192-cfb"
	AES256CFB = "aes-256-cfb"
	AES128CTR = "aes-128-ctr"
	AES192CTR = "aes-192-ctr"
	AES256CTR = "aes-256-ctr"
)

var _ciphers = map[string]ICipher{
	AES128CFB: &aesCfb{keyLen: 16, ivLen: 16},
	AES192CFB: &aesCfb{keyLen: 24, ivLen: 16},
	AES256CFB: &aesCfb{keyLen: 32, ivLen: 16},
	AES128CTR: &aesCtr{keyLen: 16, ivLen: 16},
	AES192CTR: &aesCtr{keyLen: 24, ivLen: 16},
	AES256CTR: &aesCtr{keyLen: 32, ivLen: 16},
}

func NewCipher(method, password string) (c ICipher, err error) {
	val, ok := _ciphers[method]
	if !ok {
		err = errMethod
	}
	c = val.Clone()
	err = c.Setup(password)
	return
}
