package main

import (
	client "github.com/Si-Huan/nothing/client/lib"
)

func main() {
	client := client.NewClient()
	client.Start()
}
