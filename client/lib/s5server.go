package client

import (
	"fmt"
	"io"
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
			fmt.Println("CLET ACPT    :", err)
			continue
		}

		go s.handleConn(userConn)
	}
}

func (s *Server) handleConn(userConn net.Conn) {
	defer fmt.Println("Close")
	defer userConn.Close()
	err := common.Socks5Auth(userConn)
	if err != nil {
		fmt.Println(err)
		return
	}
	eRConn, err := common.Socks5Connect(userConn, s.parent.RemoteAddr)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer eRConn.Close()
	go io.Copy(userConn, eRConn)
	io.Copy(eRConn, userConn)

}
