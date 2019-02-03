package keys

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/hainesc/roster/pkg/store"
	jose "gopkg.in/square/go-jose.v2"
)

type KeysHandler struct {
	stor store.Store
}

func NewKeysHandler(stor store.Store) *KeysHandler {
	return &KeysHandler{
		stor: stor,
	}
}

func (k *KeysHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// w.Write([]byte("Not implemented"))

	keys, _ := k.stor.GetKeys()
	jwks := jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, 1),
	}
	jwks.Keys[0] = *keys.SigningKeyPub
	data, _ := json.MarshalIndent(jwks, "", "  ")
	// TODO:
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d, must-revalidate", 3600 * 24 * 30))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}
