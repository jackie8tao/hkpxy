package obfs

import (
	"strings"

	"github.com/jackie8tao/hkpxy/ssr/spt"
)

type creator func() IObfs

var (
	creatorMap = make(map[string]creator)
)

type IObfs interface {
	SetServerInfo(s *spt.ServerInfoForObfs)
	GetServerInfo() (s *spt.ServerInfoForObfs)
	Encode(data []byte) (encodedData []byte, err error)
	Decode(data []byte) (decodedData []byte, needSendBack bool, err error)
	SetData(data interface{})
	GetData() interface{}
}

func register(name string, c creator) {
	creatorMap[name] = c
}

// NewObfs create an obfs object by name and return as an IObfs interface
func NewObfs(name string) IObfs {
	c, ok := creatorMap[strings.ToLower(name)]
	if ok {
		return c()
	}
	return nil
}
