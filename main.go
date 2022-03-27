package main

import (
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

	router.HandleFunc("/transferERC20Tokens/", transfer.ERC20()).Methods(http.MethodPost)

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
