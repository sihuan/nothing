package server

import (
	"crypto/rand"
	"errors"
	"net"

	"github.com/Si-Huan/nothing/common"
)

func (s *Server) ReadRequest(conn net.Conn) (common.Nid, []byte, error) {
	buf := make([]byte, 1024)
	var nid common.Nid

	n, err := conn.Read(buf)
	if err != nil {
		return nid, nil, errors.New("HDSK READ    " + err.Error())
	}

	buf, err = common.DecrptogRSA(buf[:n], s.Nothing.PrivateKey)
	if err != nil {
		return nid, nil, errors.New("HDSK DEPT    " + err.Error())
	}

	copy(nid[:], buf[:12])
	return nid, buf[12:], nil
}

func (s *Server) AcceptRequest(conn net.Conn) ([]byte, error) {
	metakey := make([]byte, 32)
	rand.Read(metakey)

	buf, err := common.EncyptogRSA(metakey, s.Nothing.PublicKey)
	if err != nil {
		return nil, errors.New("HDSK ENPT    " + err.Error())
	}

	_, err = conn.Write(buf)
	if err != nil {
		return nil, errors.New("HDSK WRTE    " + err.Error())
	}

	return metakey, nil
}
