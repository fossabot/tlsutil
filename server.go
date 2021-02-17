// Copyright © 2018 Acacio Cruz

package tlsutil

import (
	"crypto/tls"
	"fmt"
	"log"
)

// SetupServerTLS does basic TLS credential setup
func SetupServerTLS(tlstype, CA, crt, key string) (*tls.Config, error) {
	config := &tls.Config{}

	switch tlstype {
	case "simple":
		fallthrough
	case "simpleclients":
		fmt.Println("TLS: simple server TLS (client NOT verified!)")
		fmt.Println("TLS: cert, key: ", crt, key)
		cer, err := tls.LoadX509KeyPair(crt, key)
		if err != nil {
			log.Println(err)
			return nil, err
		}
		// config.InsecureSkipVerify = true,
		config.Certificates = []tls.Certificate{cer}

	case "certify":
		fallthrough

	case "verify":
		fallthrough

	case "certifyclients":
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = AddRootCA(CA) // Add Client CA
		fmt.Println("TLS: Validating clients with: ", CA, crt, key)
		cer, err := tls.LoadX509KeyPair(crt, key)
		if err != nil {
			log.Println(err)
			return nil, err
		}
		config.Certificates = []tls.Certificate{cer}
	default:
		log.Fatal("ERROR: unknown server TLS config type: ", tlstype)
	}
	return config, nil
}
