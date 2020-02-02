package spt

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"io"
)

func HmacMD5(key []byte, data []byte) []byte {
	hmacMD5 := hmac.New(md5.New, key)
	hmacMD5.Write(data)
	return hmacMD5.Sum(nil)[:10]
}

func HmacSHA1(key []byte, data []byte) []byte {
	hmacSHA1 := hmac.New(sha1.New, key)
	hmacSHA1.Write(data)
	return hmacSHA1.Sum(nil)[:10]
}

func SHA1Sum(d []byte) []byte {
	h := sha1.New()
	h.Write(d)
	return h.Sum(nil)
}

func MD5Sum(data []byte) []byte {
	h := md5.New()
	h.Write(data)
	return h.Sum(nil)
}

func EVPBytes2Key(password string, keyLen int) (key []byte) {
	const md5Len = 16

	cnt := (keyLen-1)/md5Len + 1
	m := make([]byte, cnt*md5Len)
	copy(m, MD5Sum([]byte(password)))

	// Repeatedly call md5 until bytes generated is enough.
	// Each call to md5 uses data: prev md5 sum + password.
	d := make([]byte, md5Len+len(password))
	start := 0
	for i := 1; i < cnt; i++ {
		start += md5Len
		copy(d, m[start-md5Len:start])
		copy(d[md5Len:], password)
		copy(m[start:], MD5Sum(d))
	}
	return m[:keyLen]
}

func IV(ivLen int) (iv []byte, err error) {
	iv = make([]byte, ivLen)
	n, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		return
	}
	if n != ivLen {
		err = errors.New("invalid random iv")
	}
	return
}
