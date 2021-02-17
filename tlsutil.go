/*
Copyright 2018 Acacio Cruz

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/grantae/certinfo"
)

// AddRootCA custom CA
func AddRootCA(CA string) *x509.CertPool {
	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	// Read in the cert file
	certs, err := ioutil.ReadFile(CA)
	if err != nil {
		log.Printf("ERROR: Failed to append %q to RootCAs: %v\n", CA, err)
	}
	// Append our cert to the system pool
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		log.Println("WARN: No certs appended, using system certs only")
	}
	fmt.Println("TLS: Loaded Certificate Authority: ", CA)
	return rootCAs
}

// CheckCertificate loads and dumps a certificate file
func CheckCertificate(crt string) {
	// Read and parse the PEM certificate file
	pemData, err := ioutil.ReadFile(crt)
	if err != nil {
		log.Fatal(err)
	}
	block, rest := pem.Decode([]byte(pemData))
	if block == nil || len(rest) > 0 {
		log.Fatal("Certificate decoding error")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	// Print the certificate
	result, err := certinfo.CertificateText(cert)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(result)
}

// AppendCertificate adds a certificate to a TLS Config
func AppendCertificate(config *tls.Config, crt, key string) error {
	fmt.Println("TLS: Loading certificates (crt, key):", crt, key)
	cer, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		log.Println(err)
		return err
	}
	config.Certificates = append(config.Certificates, cer)
	return nil
}
