package common

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

func Socks5Forward(srcConn, dstConn io.ReadWriter) {
	go io.Copy(srcConn, dstConn)
	io.Copy(dstConn, srcConn)
}

func Socks5DstAddrPort(buf []byte) (*net.TCPAddr, error) {
	n := len(buf)
	if n < 7 {
		return nil, errors.New("SDST BUFF    to short")
	}

	// CMD代表客户端请求的类型，值长度也是1个字节，有三种类型
	// CONNECT X'01'
	if buf[1] != 0x01 {
		// 目前只支持 CONNECT
		return nil, errors.New("SDST RQST    not support")
	}
	var dIP []byte
	// aType 代表请求的远程服务器地址类型，值长度1个字节，有三种类型
	switch buf[3] {
	case 0x01:
		//	IP V4 address: X'01'
		dIP = buf[4 : 4+net.IPv4len]
	case 0x03:
		//	DOMAINNAME: X'03'
		ipAddr, err := net.ResolveIPAddr("ip", string(buf[5:n-2]))
		if err != nil {
			return nil, errors.New("SDST RVIP   " + err.Error())
		}
		dIP = ipAddr.IP
	case 0x04:
		//	IP V6 address: X'04'
		dIP = buf[4 : 4+net.IPv6len]
	default:
		return nil, errors.New("SDST ADDR    not support")
	}
	dPort := buf[n-2:]
	dstAddr := &net.TCPAddr{
		IP:   dIP,
		Port: int(binary.BigEndian.Uint16(dPort)),
	}
	return dstAddr, nil
}
