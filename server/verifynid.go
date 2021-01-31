package server

import (
	"errors"
	"time"

	"github.com/Si-Huan/nothing/common"
)

type VerifyNid struct {
	nid        common.Nid
	resultChan chan error
}

func NewVerifyNid(n common.Nid) *VerifyNid {
	v := new(VerifyNid)
	v.nid = n
	v.resultChan = make(chan error)
	return v
}

func (s *Server) VerifyNid(nid common.Nid) error {
	if time.Now().UnixNano()-nid.UnixNano() > 16000000000 {
		return errors.New("NID VRFY    Too old")
	}
	v := NewVerifyNid(nid)
	s.verifyChan <- v
	return <-v.resultChan
}

func (s *Server) findNid(nid common.Nid) bool {
	for _, nnid := range s.Nids {
		if nid == nnid {
			return true
		}
	}
	return false
}

func (s *Server) UeqNid() {
	i := 0
	for verifyNid := range s.verifyChan {
		if s.findNid(verifyNid.nid) {
			verifyNid.resultChan <- errors.New("NID UEQU    Same nid")
		} else {
			if i == 255 {
				// runtime.GC()
				i = 0
			}
			s.Nids[i] = verifyNid.nid
			i++
			verifyNid.resultChan <- nil
		}
		close(verifyNid.resultChan)
	}
}
