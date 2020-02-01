package spt

import "fmt"

const _Version = "0.0.1"

//Version get shadowsocks version string
func Version() string {
	return fmt.Sprintf("shadowsocks version %s", _Version)
}
