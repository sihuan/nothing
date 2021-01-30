package server

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/Si-Huan/nothing/common"
	es "github.com/nknorg/encrypted-stream"
)

type Server struct {
	Nids       [256]common.Nid
	ListenAddr string
	verifyChan chan *verifyNid
}

type verifyNid struct {
	nid        common.Nid
	resultChan chan error
}

func NewServer() *Server {
	s := new(Server)
	s.verifyChan = make(chan *verifyNid, 5)
	s.ListenAddr = os.Getenv("NOTHING_LADDR")
	return s
}

func NewverifyNid(n common.Nid) *verifyNid {
	v := new(verifyNid)
	v.nid = n
	v.resultChan = make(chan error)
	return v
}

func (s *Server) Start() {
	listener, err := net.Listen("tcp", s.ListenAddr)
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
	defer fmt.Println("close")
	defer conn.Close()
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Server Read first Buf ERR:", err)
		return
	}
	data, err := common.DecrptogRSA(buf[:n], "sprivateKey.pem")
	if err != nil {
		fmt.Println("Server Decrpt first Buf ERR:", err)
		return
	}
	var nid common.Nid
	copy(nid[:], data[:12])
	err = s.verifyNid(nid)
	if err != nil {
		fmt.Println(err)
		return
	}
	destbuf := make([]byte, len(data)-12)
	copy(destbuf, data[12:])
	destAddrPort, _ := common.Socks5DestAddrPort(destbuf)
	fmt.Println(destAddrPort)
	dest, err := net.Dial("tcp", destAddrPort)
	if err != nil {
		fmt.Println("Server Dial Dest ERR:", err)
		return
	}
	defer dest.Close()
	var key [32]byte
	rand.Read(key[:])
	data, _ = common.EncyptogRSA(key[:], "cpublicKey.pem")
	_, err = conn.Write(data)
	if err != nil {
		fmt.Println("Server Write RSA key ERR:", err)
		return
	}
	config := &es.Config{
		Cipher: es.NewXSalsa20Poly1305Cipher(&key),
	}
	encryptedConn, err := es.NewEncryptedStream(conn, config)
	if err != nil {
		panic(err)
	}
	// common.Socks5Forward(dest, encryptedConn)

	go io.Copy(encryptedConn, dest)
	io.Copy(dest, encryptedConn)

}

func (s *Server) verifyNid(nid common.Nid) error {
	if time.Now().UnixNano()-common.BytesToInt64(nid[:8]) > 16000000000 {
		return errors.New("NID VRFY    Too old")
	}
	v := NewverifyNid(nid)
	s.verifyChan <- v
	return <-v.resultChan
}

func (s *Server) findNid(nid common.Nid) bool {
	for _, nnid := range s.Nids {
		if nid == nnid {
			return true
		}
	}
	return false
}

func (s *Server) UeqNid() {
	i := 0
	for verifyNid := range s.verifyChan {
		if s.findNid(verifyNid.nid) {
			verifyNid.resultChan <- errors.New("NID UEQU    Same nid")
		} else {
			if i == 255 {
				i = 0
			}
			s.Nids[i] = verifyNid.nid
			i++
			verifyNid.resultChan <- nil
		}
	}
}
