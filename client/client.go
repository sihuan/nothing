package client

import "github.com/Si-Huan/nothing/common"

type Client struct {
	Socks5Server *Server
	Nothing      *common.Nothing
}

func NewClient(config *common.Config) (c *Client, err error) {
	c = new(Client)
	c.Nothing, err = config.NewNothing()
	if err != nil {
		return nil, err
	}

	c.Socks5Server = NewServer(c)

	return c, nil
}

func (c *Client) Start() {
	c.Socks5Server.Start()
}
