package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"rfc20TokenTransfer/transfer"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	router := mux.NewRouter()
	///////////////////////////////////////////////////////////
	client, _ := GetETHClient()
	_ = client

	privateKey, err := crypto.HexToECDSA(os.Getenv("KEY"))
	if err != nil {
		return TxAnswer{}, errors.New("Error with privateKey: " + err.Error())
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return TxAnswer{}, errors.New("Error with getting publicKeyECDSA from private key: ")
	}
	///////////////////////////////////////////////////////////

	router.HandleFunc("/transferERC20Tokens/", ERC20TransferSystem()).Methods(http.MethodPost)

	router.Use(mux.CORSMethodMiddleware(router))
	c := cors.New(cors.Options{
		AllowedOrigins: CorsWhiteList,
		AllowedMethods: []string{http.MethodPost},
	})

	handler := c.Handler(router)
	// fmt.Println(CorsWhiteList)
	// fmt.Printf("Starting server for testing HTTP POST on port = %v...\n", os.Getenv("HTTP_ADDR"))
	log.Fatal(http.ListenAndServe("localhost:"+os.Getenv("HTTP_ADDR"), handler))
}

// var tokenAddress string = "0x714edfC7b5896397905CED2b760B3754Ef8E5e01"
// var tokenDecimal uint64 = 1000000000000000000
