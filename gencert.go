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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"time"
)

// GenerateUserCert builds a certificate from a parent cert
func GenerateUserCert(crt, key, username string) (*tls.Certificate, error) {

	parent, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		// SerialNumber: serialNumber, TODO: fix sumber generation
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
			CommonName:   username, // Will be checked by the server
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, parent.Leaf, pk.Public(), parent.PrivateKey)
	if err != nil {
		return nil, err
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert},
		PrivateKey:  pk,
	}
	return &tlsCert, nil
}

/*
p, ok := peer.FromContext(ctx)
if !ok {
	return status.Error(codes.Unauthenticated, "no peer found")
}

tlsAuth, ok := p.AuthInfo.(credentials.TLSInfo)
if !ok {
	return status.Error(codes.Unauthenticated, "unexpected peer transport credentials")
}

if len(tlsAuth.State.VerifiedChains) == 0 || len(tlsAuth.State.VerifiedChains[0]) == 0 {
	return status.Error(codes.Unauthenticated, "could not verify peer certificate")
}

// Check subject common name against configured username
if tlsAuth.State.VerifiedChains[0][0].Subject.CommonName != a.Username {
	return status.Error(codes.Unauthenticated, "invalid subject common name")
}

return nil
*/
