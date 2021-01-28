package server

import (
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/Si-Huan/nothing/common"
)

type Server struct {
	Nids       []common.Nid
	ListenAddr string
}

func NewServer() *Server {
	s := new(Server)
	s.Nids = make([]common.Nid, 0)
	s.ListenAddr = os.Getenv("NOTHING_LADDR")
	return s
}

func (s *Server) Start() {
	listener, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		panic(err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	buf := make([]byte, 1500)
	n, _ := conn.Read(buf)
	data, _ := common.DecrptogRSA(buf[:n], "sprivateKey.pem")
	var nid common.Nid
	copy(nid[:], data[:12])
	if !s.UeqNid(nid) {
		return
	}
	s.Nids = append(s.Nids, nid)
	destbuf := make([]byte, len(data)-12)
	copy(destbuf, data[12:])
	destAddrPort, _ := common.Socks5DestAddrPort(destbuf)
	fmt.Println(destAddrPort)
	dest, err := net.Dial("tcp", destAddrPort)
	if err != nil {
		return
	}
	key := make([]byte, 256)
	rand.Read(key)
	data, _ = common.EncyptogRSA(key, "cpublicKey.pem")
	cipher := common.NewCipher(key, nid)
	conn.Write(data)
	common.Socks5Forward(dest, conn, cipher)
	s.findNidAndRemove(nid)
}

func (s *Server) UeqNid(nid common.Nid) bool {
	if time.Now().UnixNano()-common.BytesToInt64(nid[:8]) > 30000000000 {
		return false
	}
	for _, nnid := range s.Nids {
		if nid == nnid {
			return false
		}
	}
	return true
}

func (s *Server) findNidAndRemove(nid common.Nid) {
	idx := -1
	for i, nnid := range s.Nids {
		if nid == nnid {
			idx = i
			break
		}
	}
	s.Nids = append(s.Nids[:idx], s.Nids[idx+1:]...)
}
