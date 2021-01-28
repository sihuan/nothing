package client

import (
	"log"
	"net"

	"github.com/Si-Huan/nothing/common"
)

type Server struct {
	parent *Client
}

func NewServer(parent *Client) *Server {
	s := new(Server)
	s.parent = parent

	return s
}

func (s *Server) Start() {
	listener, err := net.Listen("tcp", s.parent.LocalSocks5Addr)
	if err != nil {
		panic(err)
	}

	for {
		userConn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		go s.handleConn(userConn)
	}
}

func (s *Server) handleConn(userConn net.Conn) {
	common.Socks5Auth(userConn)
	remoteConn, cipher, _ := common.Socks5Connect(userConn, s.parent.RemoteAddr)
	common.Socks5Forward(userConn, remoteConn, cipher)
}
