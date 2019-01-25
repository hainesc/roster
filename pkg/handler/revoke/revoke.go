package revoke

import (
	"net/http"
)

type RevokeHandler struct {
}

func NewRevokeHandler() *RevokeHandler {
	return &RevokeHandler{}
}

func (h *RevokeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Not implemented"))
}
