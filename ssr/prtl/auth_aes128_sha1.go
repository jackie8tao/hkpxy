package prtl

import "github.com/jackie8tao/hkpxy/ssr/spt"

func init() {
	register("auth_aes128_sha1", newAuthAES128SHA1)
}

func newAuthAES128SHA1() IProtocol {
	a := &authAES128{
		salt:       "auth_aes128_sha1",
		hmac:       spt.HmacSHA1,
		hashDigest: spt.SHA1Sum,
		packID:     1,
		recvID:     1,
		data: &authData{
			connectionID: 0xFF000001,
		},
	}
	return a
}
