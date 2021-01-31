package main

import (
	"flag"

	"github.com/Si-Huan/nothing/common"
)

var config = new(common.Config)

func init() {
	flag.StringVar(&config.Client, "c", "", "client connect adress")
	flag.StringVar(&config.Server, "s", "", "server listen address")
	flag.StringVar(&config.Cipher, "e", "chacha20poly1305", "cipher type")
	flag.StringVar(&config.PrivateKey, "key", "nothing.key", "self privatekey file path")
	flag.StringVar(&config.PublicKey, "pub", "nothing.pub", "the other publickey file path")
}
