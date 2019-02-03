package memory

import (
	"crypto/rsa"
	"github.com/hainesc/roster/pkg/keys"
	"github.com/hainesc/roster/pkg/store"
	"gopkg.in/square/go-jose.v2"
)

type Memory struct {
	k keys.Keys
}

// Memory implements the Store interface
var _ store.Store = &Memory{}

func (m *Memory) RotateKeys() error {
	// TODO: just generator a rsa key, no rotation implemented.
	tmp, _ := keys.RS256.Generator()
	key := tmp.(*rsa.PrivateKey)
	priv := &jose.JSONWebKey{
		Key: key,
		KeyID: "1",
		Algorithm: "RS256",
		Use: "sig",
	}
	pub := &jose.JSONWebKey{
		Key: key.Public(),
		KeyID: "1",
		Algorithm: "RS256",
		Use: "sig",
	}

	m.k = keys.Keys{
		SigningKey: priv,
		SigningKeyPub: pub,
	}
	return nil
}

func (m *Memory) GetKeys() (keys.Keys, error) {
	// TODO:
	return m.k, nil
}
