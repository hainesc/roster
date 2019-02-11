package code

type Code struct {
	CodeID    string
	ClientID  string
	UserName  string  // claim
	Scope     []string
	Nonce     string
}
