package prtl

import (
	"github.com/jackie8tao/hkpxy/ssr/spt"
)

func init() {
	register("origin", newOrigin)
}

type origin struct {
	spt.ServerInfoForObfs
}

func newOrigin() IProtocol {
	a := &origin{}
	return a
}

func (o *origin) SetServerInfo(s *spt.ServerInfoForObfs) {
	o.ServerInfoForObfs = *s
}

func (o *origin) GetServerInfo() (s *spt.ServerInfoForObfs) {
	return &o.ServerInfoForObfs
}

func (o *origin) PreEncrypt(data []byte) (encryptedData []byte, err error) {
	return data, nil
}

func (o *origin) PostDecrypt(data []byte) (decryptedData []byte, err error) {
	return data, nil
}

func (o *origin) SetData(data interface{}) {

}

func (o *origin) GetData() interface{} {
	return nil
}
