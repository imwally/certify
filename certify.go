package main

import (
	"crypto/tls"
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

func printTLSInfo(state tls.ConnectionState) {

	version := TLSVersion[state.Version]
	suite := TLSCipherSuite[state.CipherSuite]

	fmt.Println("Version: ", version)
	fmt.Println("Cipher Suite: ", suite)
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
	found, err := findURL(s)
	if err != nil {
		log.Fatal(err)
		return
	}

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
}

func main() {

	if len(os.Args) < 2 {
		fmt.Println("certify: no command given")
		return
	}

	Certify(os.Args[1:])
}
