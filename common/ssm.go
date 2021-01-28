package common

import (
	"io"
	"net"
)

const (
	BufSize = 1024
)

// 从输入流里读取加密过的数据，解密后把原数据放到bs里
func (c *Cipher) DecodeRead(src net.Conn, bs []byte) (n int, err error) {
	n, err = src.Read(bs)
	if err != nil {
		return
	}
	c.decode(bs[:n])
	return
}

// 把放在bs里的数据加密后立即全部写入输出流
func (c *Cipher) EncodeWrite(dst net.Conn, bs []byte) (int, error) {
	c.encode(bs)
	return dst.Write(bs)
}

// 从src中源源不断的读取原数据加密后写入到dst，直到src中没有数据可以再读取
func (c *Cipher) EncodeCopy(src net.Conn, dst net.Conn) error {
	buf := make([]byte, BufSize)
	for {
		readCount, errRead := src.Read(buf)
		if errRead != nil {
			if errRead != io.EOF {
				return errRead
			} else {
				return nil
			}
		}
		if readCount > 0 {
			writeCount, errWrite := c.EncodeWrite(dst, buf[0:readCount])
			if errWrite != nil {
				return errWrite
			}
			if readCount != writeCount {
				return io.ErrShortWrite
			}
		}
	}
}

// 从src中源源不断的读取加密后的数据解密后写入到dst，直到src中没有数据可以再读取
func (c *Cipher) DecodeCopy(src net.Conn, dst net.Conn) error {
	buf := make([]byte, BufSize)
	for {
		readCount, errRead := c.DecodeRead(src, buf)
		if errRead != nil {
			if errRead != io.EOF {
				return errRead
			} else {
				return nil
			}
		}
		if readCount > 0 {
			writeCount, errWrite := dst.Write(buf[0:readCount])
			if errWrite != nil {
				return errWrite
			}
			if readCount != writeCount {
				return io.ErrShortWrite
			}
		}
	}
}
