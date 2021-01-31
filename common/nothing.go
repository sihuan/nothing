package common

import (
	"crypto/rsa"
	"net"
)

type Nothing struct {
	LocalAddr  *net.TCPAddr
	ServerAddr *net.TCPAddr
	CipherID   int
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}
