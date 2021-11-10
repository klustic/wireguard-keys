package main

// TODO: Flag for string to search for
// TODO: Flag for case insensitivity

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type keypair struct {
	PublicKey  string
	PrivateKey string
}

func main() {
	termPtr := flag.String("term", "feeb/", "The string to match in the public key")
	workersPtr := flag.Int("workers", 4, "The number of concurrent workers")
	countPtr := flag.Int("count", 0, "Limit the number of results")
	casePtr := flag.Bool("c", false, "Ignore case in the public key")
	flag.Parse()

	threadChan := make(chan int, *workersPtr)
	stopChan := make(chan int)
	resultsChan := make(chan keypair)

	resultsCtr := 0

	go func() {
		_ = <-stopChan
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}()

	go func() {
		for ; *countPtr == 0 || resultsCtr < *countPtr; resultsCtr += 1 {
			result := <-resultsChan
			fmt.Printf("Private Key: %s\tPublic Key: %s\n", result.PrivateKey, result.PublicKey)
		}
		stopChan <- 1
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
