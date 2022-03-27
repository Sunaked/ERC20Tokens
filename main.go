package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"rfc20TokenTransfer/transfer"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

//CorsWhiteList is a list of addresses that are allowed to the CORS.
var CorsWhiteList = []string{"http://localhost:8080/transferERC20Tokens/"}

type txAnswer struct {
	GasPrice        *big.Int `json:"gasprice,*big.Int"`
	GasLimit        uint64   `json:"gaslimit,uint64"`
	Nonce           uint64   `json:"nonce,uint64"`
	TransactionHash string   `json:"TransactionHash,string"`
}

type messageGet struct {
	Reciever string `json:"reciever"`
	Amount   uint64 `json:"amount"`
}

type messagePost struct {
	Errors bool     `json:"errors,bool"`
	Answer txAnswer `json:"answer"`
}

type messagePOSTerror struct {
	Errors bool   `json:"errors,bool"`
	Reason string `json:"reason"`
}

func setCORSWhitelist(w http.ResponseWriter) {
	for _, val := range CorsWhiteList {
		w.Header().Set("Access-Control-Allow-Origin", val)
	}
}

// type Token struct {
// 	ethclient *ethclient.Client
// 	publicKey string
// }

func main() {
	router := mux.NewRouter()

	// IMPORTANT: you must specify an OPTIONS method matcher for the middleware to set CORS headers
	router.HandleFunc("/transferERC20Tokens/", ERC20Tokens).Methods(http.MethodPost)

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

var tokenAddress string = "0x714edfC7b5896397905CED2b760B3754Ef8E5e01"
var tokenDecimal uint64 = 1000000000000000000

//ERC20Tokens gets a POST request with receiver hash and amount of tokens to send, then it proceeds it to the blockchain
// gets response from it and sends back information to the server in JSON format.
func ERC20Tokens(w http.ResponseWriter, r *http.Request) {
	setCORSWhitelist(w)
	body, _ := ioutil.ReadAll(r.Body)
	var u messageGet
	err := json.Unmarshal(body, &u)
	if err != nil {
		formData := messagePOSTerror{Errors: true, Reason: fmt.Sprint(err)}
		data, err := json.Marshal(formData)
		if err != nil {
			formData := messagePOSTerror{Errors: true, Reason: fmt.Sprint(err)}
			data, _ = json.Marshal(formData)
			w.Write(data)
			return
		}
		w.Write(data)
		return
	}

	txAnswer, err := tokenTransfer(u.Reciever, u.Amount)
	if err != nil {
		formData := messagePOSTerror{Errors: true, Reason: fmt.Sprint(err)}
		data, _ := json.Marshal(formData)
		w.Write(data)
		return
	}
	formData := messagePost{Errors: false, Answer: txAnswer}
	data, err := json.Marshal(formData)
	if err != nil {
		formData := messagePOSTerror{Errors: true, Reason: fmt.Sprint(err)}
		data, _ = json.Marshal(formData)
		w.Write(data)
		return
	}
	w.Write(data)
}

func tokenTransfer(reciever string, amount uint64) (txAnswer, error) {
	TxAnswer, err := transfer.SendERC20Token(reciever, tokenAddress, amount, tokenDecimal)
	return txAnswer{GasPrice: TxAnswer.GasPrice, GasLimit: TxAnswer.GasLimit, Nonce: TxAnswer.Nonce, TransactionHash: TxAnswer.TransactionHash}, err
}
