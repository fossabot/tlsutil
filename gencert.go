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
