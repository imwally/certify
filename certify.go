package main

import (
	"crypto/tls"
	"errors"
	"log"
	"net/url"
	"os"
	"regexp"
)

func getHost(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		log.Fatal(err)
	}

	return u.Host
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

func main() {

	command := os.Args[1:]

	found, err := findURL(command)
	if err != nil {
		log.Fatal(err)
		return
	}

	host := getHost(found)

	conn, err := tls.Dial("tcp", host+":443", nil)
	if err != nil {
		log.Fatal(err.Error())
	}

}
