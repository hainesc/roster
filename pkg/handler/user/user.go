package user

import (
	"net/http"
)

type UserHandler struct {
}

func NewUserHandler() *UserHandler {
	return &UserHandler{}
}

func (u *UserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Not implemented"))
}
