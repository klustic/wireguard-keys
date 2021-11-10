package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	NumWorkers = 12
)

type keypair struct {
	PublicKey  string
	PrivateKey string
}

func main() {
	termPtr := flag.String("term", "feeb/", "The string to match in the public key")
	casePtr := flag.Bool("c", false, "Ignore case in the public key")
	flag.Parse()

	threadChan := make(chan int, NumWorkers)
	stopChan := make(chan int)
	resultsChan := make(chan keypair)

	go func() {
		_ = <-stopChan
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}()

	go func() {
		for {
			result := <-resultsChan
			fmt.Printf("Private Key: %s\tPublic Key: %s\n", result.PrivateKey, result.PublicKey)
		}
	}()

	for {
		threadChan <- 1

		go func() {
			result := keypair{}
			term := *termPtr
			if *casePtr {
				term = strings.ToLower(term)
			}
			for {
				key, err := wgtypes.GeneratePrivateKey()
				if err != nil {
					log.Fatal("Error encountered while generating private key")
				}
				result.PrivateKey = key.String()
				result.PublicKey = key.PublicKey().String()
				pubTestKey := result.PublicKey

				if *casePtr {
					pubTestKey = strings.ToLower(pubTestKey)
				}

				if strings.HasPrefix(pubTestKey, term) {
					resultsChan <- result
				}
			}
		}()
	}
}
