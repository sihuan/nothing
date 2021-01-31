package server

import (
	"fmt"
	"log"
	"net"

	"github.com/Si-Huan/nothing/common"
)

type Server struct {
	Nids       [256]common.Nid
	verifyChan chan *VerifyNid

	Nothing *common.Nothing
}

func NewServer(config *common.Config) (s *Server, err error) {
	s = new(Server)
	s.Nothing, err = config.NewNothing()
	if err != nil {
		return nil, err
	}

	s.verifyChan = make(chan *VerifyNid, 5)
	return s, nil
}

func (s *Server) Start() {
	listener, err := net.ListenTCP("tcp", s.Nothing.ServerAddr)
	if err != nil {
		panic(err)
	}

	go s.UeqNid()

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
	defer conn.Close()

	nid, dstbuf, err := s.ReadRequest(conn)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = s.VerifyNid(nid)
	if err != nil {
		fmt.Println(err)
		return
	}

	dstAddr, _ := common.Socks5DstAddrPort(dstbuf)
	fmt.Println(dstAddr.String())
	defer fmt.Println("Close ", dstAddr.String())

	dst, err := net.DialTCP("tcp", nil, dstAddr)
	if err != nil {
		fmt.Println("DIAL DEST    ", err)
		return
	}
	defer dst.Close()

	metakey, err := s.AcceptRequest(conn)
	if err != nil {
		fmt.Println(err)
		return
	}

	encryptedConn, err := common.ConnEncrypt(conn, metakey, 1)
	if err != nil {
		fmt.Println("CONN ENPT    ", err)
		return
	}

	common.Socks5Forward(encryptedConn, dst)

}
