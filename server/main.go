package main

import server "github.com/Si-Huan/nothing/server/lib"

func main() {
	server := server.NewServer()
	server.Start()
}
