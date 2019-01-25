package auth

import (
	"net/http"
)

type AuthHandler struct {
}

func NewAuthHandler() *AuthHandler {
	return &AuthHandler{}
}

func (a *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Not implemented"))
}
