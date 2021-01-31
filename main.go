package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	local "github.com/Si-Huan/nothing/client"
	"github.com/Si-Huan/nothing/common"
	server "github.com/Si-Huan/nothing/server"
)

func main() {
	listCiphers := flag.Bool("listcipher", false, "List supported ciphers")
	genKey := flag.Bool("genkey", false, "Generate key file")
	flag.Parse()

	if *genKey {
		common.RSAGenKey(4096, "nothing_c")
		common.RSAGenKey(4096, "nothing_s")
		return
	}

	if *listCiphers {
		println(strings.Join(common.ListCipher(), " "))
		return
	}

	if len(config.Client) == 0 && len(config.Server) == 0 {
		flag.Usage()
		return
	}

	if len(config.Client) > 0 {
		runclient()
	}

	if len(config.Server) > 0 {
		runserver()
	}
}

func runclient() {
	client, err := local.NewClient(config)
	if err != nil {
		fmt.Println("致命错误:", err)
		os.Exit(-1)
	}
	client.Start()
}

func runserver() {
	server, err := server.NewServer(config)
	if err != nil {
		fmt.Println("致命错误:", err)
		os.Exit(-1)
	}
	server.Start()
}
