package obfs

import (
	"crypto/hmac"
	"encoding/binary"
	"math/rand"
	"strings"
	"time"

	"github.com/jackie8tao/hkpxy/ssr/spt"
	log "github.com/sirupsen/logrus"
)

func init() {
	register("tls1.2_ticket_auth", newTLS12TicketAuth)
}

type tlsAuthData struct {
	localClientID [32]byte
}

// tls12TicketAuth tls1.2_ticket_auth obfs encapsulate
type tls12TicketAuth struct {
	spt.ServerInfoForObfs
	data            *tlsAuthData
	sendID          int
	handshakeStatus int
	sendBuffer      []byte
	recvBuffer      []byte
}

// newTLS12TicketAuth create a tlv1.2_ticket_auth object
func newTLS12TicketAuth() IObfs {
	return &tls12TicketAuth{
		data: &tlsAuthData{},
	}
}

func (t *tls12TicketAuth) SetServerInfo(s *spt.ServerInfoForObfs) {
	t.ServerInfoForObfs = *s
}

func (t *tls12TicketAuth) GetServerInfo() (s *spt.ServerInfoForObfs) {
	return &t.ServerInfoForObfs
}

func (t *tls12TicketAuth) SetData(data interface{}) {
	if auth, ok := data.(*tlsAuthData); ok {
		t.data = auth
	}
}

func (t *tls12TicketAuth) GetData() interface{} {
	if t.data == nil {
		t.data = &tlsAuthData{}
		b := make([]byte, 32)
		rand.Read(b)
		copy(t.data.localClientID[:], b)
	}
	return t.data
}

func (t *tls12TicketAuth) Encode(data []byte) (encodedData []byte, err error) {
	if t.handshakeStatus == -1 {
		return data, nil
	}
	dataLength := len(data)

	if t.handshakeStatus == 8 {
		encodedData = make([]byte, dataLength+4096)
		start := 0
		outLength := 0

		for t.sendID <= 4 && dataLength-start > 256 {
			length := rand.Intn(512) + 64
			if length > dataLength-start {
				length = dataLength - start
			}
			copy(encodedData[outLength:], []byte{0x17, 0x3, 0x3})
			binary.BigEndian.PutUint16(encodedData[outLength+3:], uint16(length&0xFFFF))
			copy(encodedData[outLength+5:], data[start:start+length])
			start += length
			outLength += length + 5
			t.sendID++
		}
		for dataLength-start > 2048 {
			length := rand.Intn(4096) + 100
			if length > dataLength-start {
				length = dataLength - start
			}
			copy(encodedData[outLength:], []byte{0x17, 0x3, 0x3})
			binary.BigEndian.PutUint16(encodedData[outLength+3:], uint16(length&0xFFFF))
			copy(encodedData[outLength+5:], data[start:start+length])
			start += length
			outLength += length + 5
			t.sendID++
		}
		if dataLength-start > 0 {
			length := dataLength - start
			copy(encodedData[outLength:], []byte{0x17, 0x3, 0x3})
			binary.BigEndian.PutUint16(encodedData[outLength+3:], uint16(length&0xFFFF))
			copy(encodedData[outLength+5:], data[start:start+length])
			// not necessary to update variable *start* any more
			outLength += length + 5
			t.sendID++
		}
		encodedData = encodedData[:outLength]
		return
	}

	if t.handshakeStatus == 1 {
		//outLength := 0
		if dataLength > 0 {
			b := make([]byte, len(t.sendBuffer)+dataLength+5)
			copy(b, t.sendBuffer)
			copy(b[len(t.sendBuffer):], []byte{0x17, 0x3, 0x3})
			binary.BigEndian.PutUint16(b[len(t.sendBuffer)+3:], uint16(dataLength&0xFFFF))
			copy(b[len(t.sendBuffer)+5:], data)
			t.sendBuffer = b
			return []byte{}, nil
		}

		hmacData := make([]byte, 43)
		rnd := make([]byte, 22)
		rand.Read(rnd)

		handshakeFinish := []byte("\x14\x03\x03\x00\x01\x01\x16\x03\x03\x00\x20")
		copy(hmacData, handshakeFinish)
		copy(hmacData[len(handshakeFinish):], rnd)

		h := t.hmacSHA1(hmacData[:33])
		copy(hmacData[33:], h)

		encodedData = make([]byte, len(hmacData)+len(t.sendBuffer))
		copy(encodedData, hmacData)
		copy(encodedData[len(hmacData):], t.sendBuffer)
		t.sendBuffer = nil
		t.handshakeStatus = 8

		return
	}

	rnd := t.packAuthData()

	tlsData0 := []byte("\x00\x1c\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\xcc\x14\xcc\x13\xc0\x0a\xc0\x14\xc0\x09\xc0\x13\x00\x9c\x00\x35\x00\x2f\x00\x0a\x01\x00")
	tlsData1 := []byte("\xff\x01\x00\x01\x00")
	tlsData2 := []byte("\x00\x17\x00\x00\x00\x23\x00\xd0")
	tlsData3 := []byte("\x00\x0d\x00\x16\x00\x14\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x03\x01\x03\x03\x02\x01\x02\x03\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x12\x00\x00\x75\x50\x00\x00\x00\x0b\x00\x02\x01\x00\x00\x0a\x00\x06\x00\x04\x00\x17\x00\x18" +
		"\x00\x15\x00\x66\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

	var sslBuf []byte
	sslBuf = append(sslBuf, rnd...)
	sslBuf = append(sslBuf, byte(32))
	sslBuf = append(sslBuf, t.data.localClientID[:]...)
	sslBuf = append(sslBuf, tlsData0...)

	var extBuf []byte
	extBuf = append(extBuf, tlsData1...)

	host := t.Host
	if len(t.Param) > 0 {
		hosts := strings.Split(t.Param, ",")
		if len(hosts) > 0 {
			host = hosts[rand.Intn(len(hosts))]
			host = strings.TrimSpace(host)
		}
	}
	if len(host) > 0 && host[len(host)-1] >= byte('0') && host[len(host)-1] <= byte('9') && len(t.Param) == 0 {
		host = ""
	}
	extBuf = append(extBuf, t.sni(host)...)
	extBuf = append(extBuf, tlsData2...)
	ticket := make([]byte, 208)
	rand.Read(ticket)
	extBuf = append(extBuf, ticket...)
	extBuf = append(extBuf, tlsData3...)
	extBuf = append([]byte{byte(len(extBuf) / 256), byte(len(extBuf) % 256)}, extBuf...)

	sslBuf = append(sslBuf, extBuf...)
	// client version
	sslBuf = append([]byte{3, 3}, sslBuf...)
	// length
	sslBuf = append([]byte{1, 0, byte(len(sslBuf) / 256), byte(len(sslBuf) % 256)}, sslBuf...)
	// length
	sslBuf = append([]byte{byte(len(sslBuf) / 256), byte(len(sslBuf) % 256)}, sslBuf...)
	// version
	sslBuf = append([]byte{0x16, 3, 1}, sslBuf...)

	encodedData = sslBuf

	d := make([]byte, dataLength+5)
	copy(d[0:], []byte{0x17, 0x3, 0x3})
	binary.BigEndian.PutUint16(d[3:], uint16(dataLength&0xFFFF))
	copy(d[5:], data)
	b := make([]byte, len(t.sendBuffer)+len(d))
	copy(b, t.sendBuffer)
	copy(b[len(t.sendBuffer):], d)
	t.sendBuffer = b

	t.handshakeStatus = 1

	return
}

func (t *tls12TicketAuth) Decode(data []byte) (decodedData []byte, needSendBack bool, err error) {
	if t.handshakeStatus == -1 {
		return data, false, nil
	}
	dataLength := len(data)
	needSendBack = false

	if t.handshakeStatus == 8 {
		b := make([]byte, len(t.recvBuffer)+dataLength)
		copy(b, t.recvBuffer)
		copy(b[len(t.recvBuffer):], data)
		t.recvBuffer = b

		for len(t.recvBuffer) > 5 {
			if !hmac.Equal(t.recvBuffer[0:3], []byte{0x17, 0x3, 0x3}) {
				log.Error("incorrect magic number", t.recvBuffer[0:3], ", 0x170303 is expected")
				return nil, false, spt.ErrTLS12TicketAuthIncorrectMagicNumber
			}
			size := int(binary.BigEndian.Uint16(t.recvBuffer[3:5]))
			if size+5 > len(t.recvBuffer) {
				log.Debug("unexpected data length, ", size+5, " is expected, but only got ", len(t.recvBuffer))
				break
			}
			b = make([]byte, len(decodedData)+size)
			copy(b, decodedData)
			copy(b[len(decodedData):], t.recvBuffer[5:5+size])
			decodedData = b

			t.recvBuffer = t.recvBuffer[size+5:]
		}
		return
	}

	if dataLength < 11+32+1+32 {
		log.Error("too short data:", dataLength)
		return nil, false, spt.ErrTLS12TicketAuthTooShortData
	}

	hash := t.hmacSHA1(data[11 : 11+22])

	if !hmac.Equal(data[33:33+spt.ObfsHMACSHA1Len], hash) {
		log.Error("hmac verification failed:", hash, data[33:33+spt.ObfsHMACSHA1Len], len(data), " bytes recevied:", data)
		return nil, false, spt.ErrTLS12TicketAuthHMACError
	}
	needSendBack = true
	return nil, true, nil
}

func (t *tls12TicketAuth) packAuthData() (outData []byte) {
	outSize := 32
	outData = make([]byte, outSize)

	now := time.Now().Unix()
	binary.BigEndian.PutUint32(outData[0:4], uint32(now))

	rand.Read(outData[4 : 4+18])

	hash := t.hmacSHA1(outData[:outSize-spt.ObfsHMACSHA1Len])
	copy(outData[outSize-spt.ObfsHMACSHA1Len:], hash)

	return
}

func (t *tls12TicketAuth) hmacSHA1(data []byte) []byte {
	key := make([]byte, t.KeyLen+32)
	copy(key, t.Key)
	copy(key[t.KeyLen:], t.data.localClientID[:])

	sha1Data := spt.HmacSHA1(key, data)
	return sha1Data[:spt.ObfsHMACSHA1Len]
}

func (t *tls12TicketAuth) sni(u string) []byte {
	bURL := []byte(u)
	length := len(bURL)
	ret := make([]byte, length+9)
	copy(ret[9:9+length], bURL)
	binary.BigEndian.PutUint16(ret[7:], uint16(length&0xFFFF))
	length += 3
	binary.BigEndian.PutUint16(ret[4:], uint16(length&0xFFFF))
	length += 2
	binary.BigEndian.PutUint16(ret[2:], uint16(length&0xFFFF))
	return ret
}
