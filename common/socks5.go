package common

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

func Socks5Auth(userClient net.Conn) (err error) {
	buf := make([]byte, 256)

	// 读取 VER 和 NMETHODS
	n, err := io.ReadFull(userClient, buf[:2])
	if n != 2 {
		return errors.New("reading header: " + err.Error())
	}

	ver, nMethods := int(buf[0]), int(buf[1])
	if ver != 5 {
		return errors.New("invalid version")
	}

	// 读取 METHODS 列表
	n, err = io.ReadFull(userClient, buf[:nMethods])
	if n != nMethods {
		return errors.New("reading methods: " + err.Error())
	}

	//TO BE CONTINUED... //无需认证
	n, err = userClient.Write([]byte{0x05, 0x00})
	if n != 2 || err != nil {
		return errors.New("write rsp err: " + err.Error())
	}

	return nil
}

func Socks5Connect(client net.Conn, remoteAddr string) (net.Conn, *Cipher, error) {
	buf := make([]byte, 256)
	n, _ := client.Read(buf)
	remoteConn, cipher, err := SDail(buf[:n], remoteAddr)
	_, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		remoteConn.Close()
		return nil, nil, errors.New("write rsp: " + err.Error())
	}
	return remoteConn, cipher, nil
}

func Socks5Forward(srcConn net.Conn, dstConn net.Conn, cipher *Cipher) {
	go cipher.DecodeCopy(dstConn, srcConn)
	cipher.EncodeCopy(srcConn, dstConn)
}

func Socks5DestAddrPort(buf []byte) (destAddrPort string, err error) {
	n := len(buf)
	if err != nil || n < 7 {
		return
	}

	// CMD代表客户端请求的类型，值长度也是1个字节，有三种类型
	// CONNECT X'01'
	if buf[1] != 0x01 {
		// 目前只支持 CONNECT
		return
	}

	var addr string
	// buf[3] 代表请求的远程服务器地址类型，值长度1个字节，有三种类型
	switch buf[3] {
	case 0x01:
		//	IP V4 address: X'01'
		addr = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
	case 0x03:
		//	DOMAINNAME: X'03'
		addr = string(buf[5 : n-2])
	case 0x04:
		//	IP V6 address: X'04'
		return "", errors.New("IPv6: no supported yet")
	default:
		return
	}
	port := binary.BigEndian.Uint16(buf[n-2:])
	destAddrPort = fmt.Sprintf("%s:%d", addr, port)
	return destAddrPort, nil
}

func SDail(destbuf []byte, remoteAddr string) (remoteConn net.Conn, cipher *Cipher, err error) {
	remoteConn, err = net.Dial("tcp", remoteAddr)
	nid := NewNid(time.Now().UnixNano())
	buf := make([]byte, 1500)
	copy(buf[:12], nid[:])
	copy(buf[12:], destbuf)
	data, _ := EncyptogRSA(buf[:12+len(destbuf)], "spublicKey.pem")
	remoteConn.Write(data)
	n, _ := remoteConn.Read(buf)
	data, _ = DecrptogRSA(buf[:n], "cprivateKey.pem")
	// fmt.Println(data)
	cipher = NewCipher(data, nid)
	return
}
