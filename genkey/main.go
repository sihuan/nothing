package main

import (
	"github.com/Si-Huan/nothing/common"
)

func main() {

	common.RSAGenKey(4096, "c")
	common.RSAGenKey(4096, "s")

}
