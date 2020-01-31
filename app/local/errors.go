package main

import "errors"

var (
	errVer  = errors.New("invalid sock5 version")
	errCmd  = errors.New("invalid command value")
	errAddr = errors.New("invalid address type")
	errData = errors.New("socks5 get extra data")
)
