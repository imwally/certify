package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
)

var TLSCipherSuite = map[uint16]string{
	tls.TLS_RSA_WITH_RC4_128_SHA:                "TLS_RSA_WITH_RC4_128_SHA",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "TLS_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:            "TLS_RSA_WITH_AES_256_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_FALLBACK_SCSV:                       "TLS_FALLBACK_SCSV",
}

var TLSVersion = map[uint16]string{
	tls.VersionSSL30: "SSL v3.0",
	tls.VersionTLS10: "TLS v1.0",
	tls.VersionTLS11: "TLS v1.1",
	tls.VersionTLS12: "TLS v1.2",
}

func printCertificateInfo(cert *x509.Certificate) {

	// Fingerprint
	fingerprint1 := sha1.Sum(cert.Raw)
	fingerprint256 := sha256.Sum256(cert.Raw)

	// Issuer
	country := cert.Issuer.Country
	organization := cert.Issuer.Organization
	organizationalUnit := cert.Issuer.OrganizationalUnit

	// Subject
	subCountry := cert.Subject.Country
	subOrganization := cert.Subject.Organization
	subOrganizationalUnit := cert.Subject.OrganizationalUnit

	// Validity
	notBefore := cert.NotBefore
	notAfter := cert.NotAfter

	fmt.Println("--- Certificate Information ---")
	fmt.Printf("\n\t% x\n", fingerprint1)
	fmt.Printf("\t% x\n", fingerprint256)
	fmt.Println("Issuer:")
	fmt.Println("\tC: ", country)
	fmt.Println("\tO: ", organization)
	fmt.Println("\tOU:", organizationalUnit)
	fmt.Println("Subject:")
	fmt.Println("\tC: ", subCountry)
	fmt.Println("\tO: ", subOrganization)
	fmt.Println("\tOU:", subOrganizationalUnit)

	fmt.Println("Valid:")
	fmt.Println("\tNot Before:", notBefore)
	fmt.Println("\tNot After: ", notAfter)

	fmt.Println()
}

func printTLSInfo(state tls.ConnectionState) {

	version := TLSVersion[state.Version]
	suite := TLSCipherSuite[state.CipherSuite]

	fmt.Println("--- TLS Information ---")
	fmt.Println("Version:\t", version)
	fmt.Println("Cipher Suite:\t", suite)

	fmt.Println()
}

func findURL(s []string) (url string, err error) {
	validURL := regexp.MustCompile(`^https://[a-z]`)

	for _, arg := range s {
		if validURL.MatchString(arg) {
			return arg, nil
		}
	}

	return "", errors.New("certify: no secure uri found")
}

func Certify(s []string) {

	// Parse command and return the first URL found.
	found, err := findURL(s)
	if err != nil {
		log.Fatal(err)
		return
	}

	// Parse URL as we only need the hostname.
	u, err := url.Parse(found)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := tls.Dial("tcp", u.Host+":443", nil)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer conn.Close()

	printTLSInfo(conn.ConnectionState())

	for _, cert := range conn.ConnectionState().PeerCertificates {
		printCertificateInfo(cert)
	}
}

func main() {

	if len(os.Args) < 2 {
		fmt.Println("certify: no command given")
		return
	}

	Certify(os.Args[1:])
}
