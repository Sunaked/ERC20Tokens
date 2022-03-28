package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"rfc20TokenTransfer/transfer"

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
	ERC20Token, err := transfer.NewToken()
	if err != nil {
		return fmt.Errorf("Error with making new token, check your configuration(privateKey or RPCURL)")
	}
	router.Handle("/transferERC20Tokens/", ERC20Token).Methods(http.MethodPost)

	router.Use(mux.CORSMethodMiddleware(router))
	c := cors.New(cors.Options{
		AllowedOrigins: transfer.CorsWhiteList,
		AllowedMethods: []string{http.MethodPost},
	})

	handler := c.Handler(router)
	// fmt.Println(CorsWhiteList)
	// fmt.Printf("Starting server for testing HTTP POST on port = %v...\n", os.Getenv("HTTP_ADDR"))
	log.Fatal(http.ListenAndServe("localhost:"+os.Getenv("HTTP_ADDR"), handler))

	return nil
}
