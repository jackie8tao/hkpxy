package cfg

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

//Addr host:port => pc address
type Addr struct {
	Host string `json:"host"`
	Port uint   `json:"port"`
}

//Config socks5 configuration
type Config struct {
	Remote   Addr   `json:"remote"`
	Local    Addr   `json:"local"`
	Method   string `json:"method"`
	Password string `json:"password"`
	Timeout  int    `json:"timeout"`
}

//Val return address value in string
func (a *Addr) Val() string {
	return fmt.Sprintf("%s:%d", a.Host, a.Port)
}

//LocalVal return local address value in string
func (c *Config) LocalVal() string {
	return c.Local.Val()
}

//RemoteVal return remote address value in string
func (c *Config) RemoteVal() string {
	return c.Remote.Val()
}

//Parse read configuration from file
func Parse(path string) (c *Config, err error) {
	cnt, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}
	c = &Config{}
	err = json.Unmarshal(cnt, c)
	return
}
