package token

import (
	"net/http"
)

type TokenHandler struct {
}

func NewTokenHandler() *TokenHandler {
	return &TokenHandler{}
}

func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Not implemented"))
}
