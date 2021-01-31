package common

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"net"
	"sort"

	es "github.com/nknorg/encrypted-stream"
	ccp "golang.org/x/crypto/chacha20poly1305"
)

const (
	chacha20poly1305 = iota
	xchacha20poly1305
	xsalsa20poly1305
	aesgcm128
	aesgcm256
)

var cipherlist = map[string]int{
	"chacha20poly1305":  chacha20poly1305,
	"xchacha20poly1305": xchacha20poly1305,
	"xsalsa20poly1305":  xsalsa20poly1305,
	"aesgcm128":         aesgcm128,
	"aesgcm256":         aesgcm256,
}

func ListCipher() []string {
	var l []string
	for k := range cipherlist {
		l = append(l, k)
	}
	sort.Strings(l)
	return l
}

func NewChaCha20Poly1305Cipher(key []byte) (*es.CryptoAEADCipher, error) {
	aead, err := ccp.New(key[:])
	if err != nil {
		return nil, err
	}
	return es.NewCryptoAEADCipher(aead), nil
}

func NewXChaCha20Poly1305Cipher(key []byte) (*es.CryptoAEADCipher, error) {
	aead, err := ccp.NewX(key[:])
	if err != nil {
		return nil, err
	}
	return es.NewCryptoAEADCipher(aead), nil
}

func ConnEncrypt(conn net.Conn, metakey []byte, cipherID int) (*es.EncryptedStream, error) {

	var cipher es.Cipher
	var err error
	switch cipherID {
	case chacha20poly1305:
		key := sha256.Sum256(metakey)
		cipher, err = NewChaCha20Poly1305Cipher(key[:])
		if err != nil {
			return nil, err
		}
	case xchacha20poly1305:
		key := sha256.Sum256(metakey)
		cipher, err = NewXChaCha20Poly1305Cipher(key[:])
		if err != nil {
			return nil, err
		}
	case xsalsa20poly1305:
		key := sha256.Sum256(metakey)
		cipher = es.NewXSalsa20Poly1305Cipher(&key)
	case aesgcm128:
		key := md5.Sum(metakey)
		cipher, err = es.NewAESGCMCipher(key[:])
		if err != nil {
			return nil, err
		}
	case aesgcm256:
		key := sha256.Sum256(metakey)
		cipher, err = es.NewAESGCMCipher(key[:])
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown cipher %v", cipherID)
	}

	config := &es.Config{
		Cipher: cipher,
	}
	encryptedConn, err := es.NewEncryptedStream(conn, config)
	if err != nil {
		return nil, err
	}
	return encryptedConn, nil
}

func LoadCipher(cipher string) (int, error) {
	if cipherID, ok := cipherlist[cipher]; ok {
		return cipherID, nil
	}

	return 0, fmt.Errorf("unknown cipher %v", cipher)

}
