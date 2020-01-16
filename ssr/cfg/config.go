package cfg

import "fmt"

//Addr host:port => pc address
type Addr struct {
	Host string
	Port uint16
}

//Config socks5 configuration
type Config struct {
	Remote Addr
	Local  Addr
	Http   Addr
}

//Val return address value in string
func (a Addr) Val() string {
	return fmt.Sprintf("%s:%d", a.Host, a.Port)
}

//LocalVal return local address value in string
func (c Config) LocalVal() string {
	return c.Local.Val()
}

//RemoteVal return remote address value in string
func (c Config) RemoteVal() string {
	return c.Remote.Val()
}