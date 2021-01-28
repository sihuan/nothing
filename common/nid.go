package common

import (
	"encoding/binary"
	"math/rand"
	"time"
)

type Nid [12]byte

func (n *Nid) UnixNano() int64 {
	return BytesToInt64(n[:8])
}

func NewNid(seed int64) Nid {
	var n Nid

	rand.Seed(seed)
	token := make([]byte, 4)
	rand.Read(token)
	timeUnixNano := time.Now().UnixNano()
	buf := make([]byte, 12)
	buf = append(Int64ToBytes(timeUnixNano), token...)
	copy(n[:], buf)
	return n
}

func Int64ToBytes(i int64) []byte {
	var buf = make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(i))
	return buf
}

func BytesToInt64(buf []byte) int64 {
	return int64(binary.BigEndian.Uint64(buf))
}