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
}

func main() {

	if len(os.Args) < 2 {
		fmt.Println("certify: no command given")
		return
	}

	Certify(os.Args[1:])
}
