package spt

import (
	"fmt"
	"reflect"
	"testing"
)

func TestMd5Sum(t *testing.T) {
	val, err := Md5Sum([]byte("foobar"))
	if err != nil {
		t.Error(err)
	}
	key := fmt.Sprintf("%x", val)
	target := "3858f62230ac3c915f300c664312c63f"
	if !reflect.DeepEqual(key, target) {
		t.Errorf("md5 value not correct\n\texpect: %v\n\tgot: %v\n", target, key)
	}
}

func TestBytes2Key(t *testing.T) {
	key, err := EvpBytes2Key("foobar", 32)
	if err != nil {
		t.Error(err)
	}
	target := []byte{
		0x38, 0x58, 0xf6, 0x22, 0x30, 0xac, 0x3c, 0x91,
		0x5f, 0x30, 0x0c, 0x66, 0x43, 0x12, 0xc6, 0x3f,
		0x56, 0x83, 0x78, 0x52, 0x96, 0x14, 0xd2, 0x2d,
		0xdb, 0x49, 0x23, 0x7d, 0x2f, 0x60, 0xbf, 0xdf,
	}
	if !reflect.DeepEqual(key, target) {
		t.Errorf("key not correct\n\texpect: %v\n\tgot: %v\n", target, key)
	}
}
