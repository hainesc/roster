package client

type Client struct {
	ID     string `json:"id" yaml:"id"`
	Secret string `json:"secret" yaml:"secret"`
	RedirectURI string `json:"redirectURI" yaml:"redirectURI"`
	Name    string `json:"name" yaml:"name"`
}
