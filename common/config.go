package common

import (
	"net"
)

type Config struct {
	Client     string
	Server     string
	Cipher     string
	PrivateKey string
	PublicKey  string
}

func (c *Config) NewNothing() (n *Nothing, err error) {
	n = new(Nothing)

	n.LocalAddr, err = net.ResolveTCPAddr("tcp", c.Client)
	if err != nil {
		return
	}

	n.ServerAddr, err = net.ResolveTCPAddr("tcp", c.Server)
	if err != nil {
		return
	}

	n.CipherID, err = LoadCipher(c.Cipher)
	if err != nil {
		return
	}

	n.PublicKey, err = LoadPublicKey(c.PublicKey)
	if err != nil {
		return
	}

	n.PrivateKey, err = LoadPrivateKey(c.PrivateKey)
	if err != nil {
		return
	}
	return n, nil
}
