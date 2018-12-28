package authenticator

import (
	github.com/hainesc/roster/pkg/mfa
)

type Authenticator struct {
}

var _ mfa.Mfa = &Authenticator{}
