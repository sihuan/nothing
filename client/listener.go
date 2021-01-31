package client

import (
	"fmt"
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
	listener, err := net.ListenTCP("tcp", s.parent.Nothing.LocalAddr)
	if err != nil {
		panic(err)
	}

	for {
		userConn, err := listener.Accept()
		if err != nil {
			fmt.Println("CLET ACPT    :", err)
			continue
		}

		go s.handleConn(userConn)
	}
}

func (s *Server) handleConn(userConn net.Conn) {
	defer fmt.Println("Close")
	defer userConn.Close()

	err := s.parent.Socks5Auth(userConn)
	if err != nil {
		fmt.Println(err)
		return
	}

	eRConn, err := s.parent.Socks5Connect(userConn)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer eRConn.Close()

	common.Socks5Forward(userConn, eRConn)

}
