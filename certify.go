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

// namesToName reduces a slice of strings to a single string
func namesToName(names []string) string {
	retName := ""
	if names == nil {
		retName = "<blank>"
	} else {
		for i, name := range names {
			retName += name
			if i != len(names)-1 {
				retName += " / "
			}
		}
	}

	return retName
}

func printCertificateInfo(cert *x509.Certificate) {

	// Subject
	sub := cert.Subject
	subCN := sub.CommonName
	subC := namesToName(sub.Country)
	subO := namesToName(sub.Organization)
	subOU := namesToName(sub.OrganizationalUnit)

	// Issuer
	issuer := cert.Issuer
	issuerCN := issuer.CommonName
	issuerC := namesToName(issuer.Country)
	issuerO := namesToName(issuer.Organization)
	issuerOU := namesToName(issuer.OrganizationalUnit)

	// Validity
	domains := namesToName(cert.DNSNames)
	notBefore := cert.NotBefore
	notAfter := cert.NotAfter

	// Fingerprint
	fingerprint1 := sha1.Sum(cert.Raw)
	fingerprint256 := sha256.Sum256(cert.Raw)

	fmt.Println("--- Certificate Information ---")

	fmt.Println("\nSubject:")
	fmt.Println("\tCN:", subCN)
	fmt.Println("\tC: ", subC)
	fmt.Println("\tO: ", subO)
	fmt.Println("\tOU:", subOU)

	fmt.Println("\nIssuer:")
	fmt.Println("\tCN:", issuerCN)
	fmt.Println("\tC: ", issuerC)
	fmt.Println("\tO: ", issuerO)
	fmt.Println("\tOU:", issuerOU)

	fmt.Println("\nValid:")
	fmt.Println("\tNot Before:", notBefore)
	fmt.Println("\tNot After: ", notAfter)
	fmt.Println("\tDomains: ", domains)

	fmt.Println("\nFingerprints:")
	fmt.Printf("\tSHA1:   %x\n", fingerprint1)
	fmt.Printf("\tSHA256: %x\n", fingerprint256)

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
		fmt.Println(err.Error())
	}
	defer conn.Close()

}

func main() {

	if len(os.Args) < 2 {
		fmt.Println("certify: no command given")
		return
	}

	Certify(os.Args[1:])
}
