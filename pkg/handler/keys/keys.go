package keys

import (
	"net/http"
)

type KeysHandler struct {
}

func NewKeysHandler() *KeysHandler {
	return &KeysHandler{}
}

func (k *KeysHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Not implemented"))
}
