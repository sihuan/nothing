package client

import "os"

type Client struct {
	Server          *Server
	LocalSocks5Addr string
	RemoteAddr      string
}

func NewClient() *Client {
	c := new(Client)
	c.Server = NewServer(c)
	c.LocalSocks5Addr = os.Getenv("NOTHING_CADDR")
	c.RemoteAddr = os.Getenv("NOTHING_SADDR")
	return c
}

func (c *Client) Start() {
	c.Server.Start()
}
