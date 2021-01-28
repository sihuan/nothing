package common

import (
	"crypto/cipher"
	"crypto/sha256"

	"golang.org/x/crypto/chacha20poly1305"
)

type Cipher struct {
	aead  cipher.AEAD
	nonce Nid
}

// 加密原数据
func (cipher *Cipher) encode(bs []byte) {
	bs = cipher.aead.Seal(nil, cipher.nonce[:], bs, nil)
}

// 解码加密后的数据到原数据
func (cipher *Cipher) decode(bs []byte) {
	bs, _ = cipher.aead.Open(nil, cipher.nonce[:], bs, nil)
}

// 新建一个编码解码器
func NewCipher(pass []byte, nonce Nid) *Cipher {
	key := sha256.Sum256(pass)
	// aead, _ := chacha20poly1305.NewX(key[:])
	aead, _ := chacha20poly1305.New(key[:])
	return &Cipher{
		aead:  aead,
		nonce: nonce,
	}
}
