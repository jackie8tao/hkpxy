package ssr

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

const (
	Version = 0x05
)

//handle socks5 stream
func sock5Handler(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		log.Println(err)
	}

	if n <= 0 {
		return
	}

	if int(buf[0]) != Version {
		log.Println("invalid version")
		return
	}

	_, err = conn.Write([]byte{byte(0x05), byte(0x00)})
	if err != nil {
		log.Println(err)
		return
	}

	n, err = conn.Read(buf)
	if err != nil && err != io.EOF {
		log.Println(err)
		return
	}
	cmd := buf[1]
	if int(cmd) == 0x01 {
		atyp := buf[3]
		if int(atyp) == 0x01 {
			addr := fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
			port := binary.BigEndian.Uint16(buf[n-2 : n])
			c, err := net.Dial("tcp", fmt.Sprintf("%s:%d", addr, port))
			if err != nil {
				log.Println(err)
				conn.Write([]byte{
					0x05, 0x04, 0x00, 0x01,
					0x00, 0x00, 0x00, 0x00,
					0x10, 0x80,
				})
				return
			}
			_, err = conn.Write([]byte{
				0x05, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00,
				0x10, 0x80,
			})
			if err != nil {
				log.Println(err)
				return
			}

			for {
				n, err := conn.Read(buf)
				if err != nil {
					if err != io.EOF {
						log.Println(err)
					}
					break
				}

				if n > 0 {
					_, err := c.Write(buf[0:n])
					if err != nil {
						log.Println(err)
					}
					for {
						n, err := c.Read(buf)
						if err != nil {
							if err != io.EOF {
								log.Println(err)
							}
							break
						}

						if n > 0 {
							_, err := conn.Write(buf[0:n])
							if err != nil {
								log.Println(err)
							}
							continue
						}
						break
					}
					continue
				}
				break
			}
		}
	}

}
