package cert

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

var (
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
)

func LoadCA(certDir string) error {
	caKeyPath := certDir + "/ca.key"
	caCertPath := certDir + "/ca.crt"
	caKeyBytes, err := os.ReadFile(caKeyPath)
	if err != nil {
		return fmt.Errorf("cannot read ca.key: %v", err)
	}
	block, _ := pem.Decode(caKeyBytes)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block in ca.key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsedKey, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return fmt.Errorf("cannot parse ca.key: %v", err)
		}
		var ok bool
		key, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("ca.key is not an RSA private key")
		}
	}

	caKey = key
	caCertBytes, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("cannot read ca.crt: %v", err)
	}
	block, _ = pem.Decode(caCertBytes)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block in ca.crt")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("cannot parse ca.crt: %v", err)
	}
	caCert = cert

	return nil
}

func GetCA() (*x509.Certificate, *rsa.PrivateKey) {
	return caCert, caKey
}
