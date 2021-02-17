// Copyright © 2018 Acacio Cruz

package tlsutil

import (
	"crypto/tls"
	"log"
)

// SetupClientTLS does basic TLS credential setup
func SetupClientTLS(tlstype, CA, crt, key string) (*tls.Config, error) {
	config := &tls.Config{}

	// Load certs unless it's simple auth
	if tlstype != "nocert" {
		if err := AppendCertificate(config, crt, key); err != nil {
			return nil, err
		}
	}

	if CA != "" {
		config.RootCAs = AddRootCA(CA)
	}

	switch tlstype {
	case "nocert":
		// fmt.Println("TLS: Using simple TLS (no client certs)")
		config.InsecureSkipVerify = true
	case "certs":
		// fmt.Println("TLS: Using certs, NO server verification")
		// certs loaded above
		config.InsecureSkipVerify = true
	case "verify":
		// fmt.Println("TLS: Using verify, WITH server verification")
		// certs loaded above
		config.InsecureSkipVerify = false
	default:
		log.Fatal("ERROR: unknown client TLS config type: ", tlstype)
	}
	return config, nil
}

// SetupClientTLSWithCA does TLS credential setup with CA & certs
func SetupClientTLSWithCA(CA, crt, key string) (*tls.Config, error) {
	config := &tls.Config{}
	if err := AppendCertificate(config, crt, key); err != nil {
		return nil, err
	}
	config.RootCAs = AddRootCA(CA)
	config.InsecureSkipVerify = false
	return config, nil
}
