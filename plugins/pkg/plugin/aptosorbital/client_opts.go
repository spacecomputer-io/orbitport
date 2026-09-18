package aptosorbital

import (
	"fmt"
	"time"
)

const (
	API_URL  = "https://api.aptosorbital.com"
	AUTH_URL = "https://auth.aptosorbital.com/oauth2/token"
)

// ClientOptions contains the configuration options for the Aptos Orbital client.
type ClientOptions struct {
	apiURL       string
	authURL      string
	clientID     string
	clientSecret string
	rateLimit    float64
	rateBurst    int
	timeout      time.Duration
}

// apply applies the given options to the ClientOptions with defaults.
func (o *ClientOptions) apply(opts ...ClientOption) error {
	for _, opt := range opts {
		opt(o)
	}
	return o.defaults()
}

// defaults sets the default values for the ClientOptions.
func (o *ClientOptions) defaults() error {
	if len(o.apiURL) == 0 {
		o.apiURL = API_URL
	}
	if len(o.authURL) == 0 {
		o.authURL = AUTH_URL
	}
	if len(o.clientID) == 0 {
		return fmt.Errorf("client ID is required")
	}
	if len(o.clientSecret) == 0 {
		return fmt.Errorf("client secret is required")
	}
	if o.rateLimit == 0.0 {
		o.rateLimit = 0.2
	}
	if o.rateBurst == 0 {
		o.rateBurst = 1
	}
	if o.timeout == 0 {
		o.timeout = 20 * time.Second
	}
	return nil
}

// ClientOption is a function that sets a configuration option.
type ClientOption func(*ClientOptions)

// WithTimeout sets the timeout for the client.
// The default value is 20 seconds.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(o *ClientOptions) {
		o.timeout = timeout
	}
}

// WithApiURL sets the API URL for the client.
// The default value is "https://api.aptosorbital.com".
func WithApiURL(apiURL string) ClientOption {
	return func(o *ClientOptions) {
		o.apiURL = apiURL
	}
}

// WithAuthURL sets the authentication URL for the client.
// The default value is "https://auth.aptosorbital.com/oauth2/token".
func WithAuthURL(authURL string) ClientOption {
	return func(o *ClientOptions) {
		o.authURL = authURL
	}
}

// WithClientID sets the client ID for the client.
// This option is REQUIRED.
func WithClientID(clientID string) ClientOption {
	return func(o *ClientOptions) {
		o.clientID = clientID
	}
}

// WithClientSecret sets the client secret for the client.
// This option is REQUIRED.
func WithClientSecret(clientSecret string) ClientOption {
	return func(o *ClientOptions) {
		o.clientSecret = clientSecret
	}
}

// WithRateLimit sets the rate limit for the client.
// The default rate limit is 0.1 requests per second with a burst of 1.
func WithRateLimit(rateLimit float64, rateBurst int) ClientOption {
	return func(o *ClientOptions) {
		o.rateLimit = rateLimit
		o.rateBurst = rateBurst
	}
}
