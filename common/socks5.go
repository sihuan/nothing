package common

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	es "github.com/nknorg/encrypted-stream"
)

func Socks5Auth(userClient net.Conn) (err error) {
	buf := make([]byte, 256)

	// 读取 VER 和 NMETHODS
	n, err := io.ReadFull(userClient, buf[:2])
	if n != 2 {
		return errors.New("SATH RVER    " + err.Error())
	}

	ver, nMethods := int(buf[0]), int(buf[1])
	if ver != 5 {
		return errors.New("SATH RVER    invalid version")
	}

	// 读取 METHODS 列表
	n, err = io.ReadFull(userClient, buf[:nMethods])
	if n != nMethods {
		return errors.New("SATH RMTH    " + err.Error())
	}

	//TO BE CONTINUED... //无需认证
	n, err = userClient.Write([]byte{0x05, 0x00})
	if n != 2 || err != nil {
		return errors.New("SATH WRTE    " + err.Error())
	}

	return nil
}

func Socks5Connect(client net.Conn, remoteAddr string) (*es.EncryptedStream, error) {
	buf := make([]byte, 256)
	n, _ := client.Read(buf)
	eRConn, err := SDail(buf[:n], remoteAddr)
	if err != nil {
		// fmt.Println("Socks5Connect SDail ERR:", err)
		return nil, err
	}
	_, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		// fmt.Println("Socks5Connect Write userConn ERR:", err)
		err = errors.New("SCON WRTE    " + err.Error())
		eRConn.Close()
		return nil, err
	}
	return eRConn, nil
}

func Socks5Forward(srcConn net.Conn, dstConn *es.EncryptedStream) {
	go io.Copy(srcConn, dstConn)
	io.Copy(dstConn, srcConn)
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
		var ip net.IP
		ip = buf[4 : 4+net.IPv6len]
		addr = "[" + ip.String() + "]"
	default:
		return
	}
	port := binary.BigEndian.Uint16(buf[n-2:])
	destAddrPort = fmt.Sprintf("%s:%d", addr, port)
	return destAddrPort, nil
}

func SDail(destbuf []byte, remoteAddr string) (*es.EncryptedStream, error) {
	remoteConn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		// fmt.Println("SDail Remote ERR:", err)
		err = errors.New("SDIL DAIL    " + err.Error())
		return nil, err
	}
	nid := NewNid()
	buf := make([]byte, 1024)
	copy(buf[:12], nid[:])
	copy(buf[12:], destbuf)
	data, err := EncyptogRSA(buf[:12+len(destbuf)], "spublicKey.pem")
	if err != nil {
		// fmt.Println("SDail Encypt ERR:", err)
		err = errors.New("SDIL ENPT    " + err.Error())
		remoteConn.Close()
		return nil, err
	}
	_, err = remoteConn.Write(data)
	if err != nil {
		// fmt.Println("SDail Remote first Write ERR:", err)
		err = errors.New("SDIL WRTE    " + err.Error())
		remoteConn.Close()
		return nil, err
	}
	n, err := remoteConn.Read(buf)
	if err != nil {
		if err == io.EOF {
			err = errors.New("Server Refuse This Dst buf")
		}
		// fmt.Println("SDail Remote first Read ERR:", err)
		err = errors.New("SDIL READ    " + err.Error())
		remoteConn.Close()
		return nil, err
	}
	data, err = DecrptogRSA(buf[:n], "cprivateKey.pem")
	if err != nil {
		// fmt.Println("SDail Decrpt ERR:", err)
		err = errors.New("SDIL DEPT    " + err.Error())
		remoteConn.Close()
		return nil, err
	}
	var key [32]byte
	copy(key[:], data)
	config := &es.Config{
		Cipher: es.NewXSalsa20Poly1305Cipher(&key),
	}
	encryptedConn, err := es.NewEncryptedStream(remoteConn, config)
	if err != nil {
		panic(err)
	}
	return encryptedConn, nil
}
