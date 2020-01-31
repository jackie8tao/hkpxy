package spt

import "crypto/md5"

func Md5Sum(data []byte) (val []byte, err error) {
	h := md5.New()
	_, err = h.Write(data)
	if err != nil {
		return
	}
	val = h.Sum(nil)
	return
}

func EvpBytes2Key(password string, keyLen int) (key []byte, err error) {
	const md5Len = 16
	var val []byte

	cnt := (keyLen-1)/md5Len + 1
	m := make([]byte, cnt*md5Len)
	val, err = Md5Sum([]byte(password))
	if err != nil {
		return
	}
	copy(m, val)

	// Repeatedly call md5 until bytes generated is enough.
	// Each call to md5 uses data: prev md5 sum + password.
	d := make([]byte, md5Len+len(password))
	for i, start := 1, 0; i < cnt; i++ {
		start += md5Len
		copy(d, m[start-md5Len:start])
		copy(d[md5Len:], password)
		val, err = Md5Sum(d)
		if err != nil {
			return
		}
		copy(m[start:], val)
	}
	key = m[:keyLen]
	return
}
