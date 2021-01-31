package client

import (
	"errors"
	"io"
	"net"

	"github.com/Si-Huan/nothing/common"
	es "github.com/nknorg/encrypted-stream"
)

func (c *Client) Socks5Auth(userClient net.Conn) (err error) {
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

func (c *Client) Socks5Connect(client net.Conn) (*es.EncryptedStream, error) {
	buf := make([]byte, 256)
	n, _ := client.Read(buf)
	eRConn, err := c.SDail(buf[:n])
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

func (c *Client) SDail(destbuf []byte) (*es.EncryptedStream, error) {
	remoteConn, err := net.DialTCP("tcp", nil, c.Nothing.ServerAddr)
	if err != nil {
		err = errors.New("SDIL DAIL    " + err.Error())
		return nil, err
	}
	nid := common.NewNid()
	buf := make([]byte, 1024)
	copy(buf[:12], nid[:])
	copy(buf[12:], destbuf)
	buf, err = common.EncyptogRSA(buf[:12+len(destbuf)], c.Nothing.PublicKey)
	if err != nil {
		err = errors.New("SDIL ENPT    " + err.Error())
		remoteConn.Close()
		return nil, err
	}
	_, err = remoteConn.Write(buf)
	if err != nil {
		err = errors.New("SDIL WRTE    " + err.Error())
		remoteConn.Close()
		return nil, err
	}
	n, err := remoteConn.Read(buf)
	if err != nil {
		if err == io.EOF {
			err = errors.New("server do not like this request")
		}
		err = errors.New("SDIL READ    " + err.Error())
		remoteConn.Close()
		return nil, err
	}
	buf, err = common.DecrptogRSA(buf[:n], c.Nothing.PrivateKey)
	if err != nil {
		err = errors.New("SDIL DEPT    " + err.Error())
		remoteConn.Close()
		return nil, err
	}
	encryptedConn, err := common.ConnEncrypt(remoteConn, buf[:32], 1)
	if err != nil {
		err = errors.New("SDIL CNET    " + err.Error())
		remoteConn.Close()
		return nil, err
	}
	return encryptedConn, nil
}
