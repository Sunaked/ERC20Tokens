package transfer

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"rfc20TokenTransfer/config"
	"sync"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/crypto/sha3"
)

//CorsWhiteList is a list of addresses that are allowed to the CORS.
var CorsWhiteList = []string{"http://localhost:8080/transferERC20Tokens/"}

//MessageGet get is a message FROM the server with POST parameters.
type MessageGet struct {
	Reciever string `json:"reciever"`
	Amount   uint64 `json:"amount"`
}

//MessagePost is a message TO server with POST parameters.
type MessagePost struct {
	Errors bool     `json:"errors,bool"`
	Answer TxAnswer `json:"answer"`
}

//MessagePOSTerror is a message TO server if error happens.
type MessagePOSTerror struct {
	Errors bool   `json:"errors,bool"`
	Reason string `json:"reason"`
}

//SetCORSWhitelist sets the CORS whitelist for the given http.ResponseWriter according to the 'CorsWhiteList'.
func SetCORSWhitelist(w http.ResponseWriter) {
	for _, val := range CorsWhiteList {
		w.Header().Set("Access-Control-Allow-Origin", val)
	}
}

//Key is a pair of public and private keys from the ethclient and is used in Token structure.
type Key struct {
	public  crypto.PublicKey
	Private string
}

// type Token interface {
// 	Transfer(,*ethclient.Client, Key)
// }

//ERC20 represents a token that implements http.Handler interface
type ERC20 struct {
	ethclient *ethclient.Client
	Key       Key
}

var (
	client *ethclient.Client
	once   sync.Once
)

//GetETHClient  creates ethclient.Client connection
func GetETHClient() (*ethclient.Client, error) {
	cfg := config.Get()
	client, err := ethclient.Dial(cfg.RPCURL)
	if err != nil {
		return nil, fmt.Errorf("Error with ethclient: %v", err)
	}
	return client, nil
}

// Transfer makes a transaction to the ethclient
func (e *ERC20) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	client := e.ethclient
	publicKey := e.Key.public
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return TxAnswer{}, errors.New("Error with getting publicKeyECDSA from private key: ")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return TxAnswer{}, errors.New("Error with nonce: " + err.Error())
	}
	// fmt.Print("nonce = ", nonce, "\n")

	value := big.NewInt(0)
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return TxAnswer{}, errors.New("Error with getting Suggested gasPrice: " + err.Error())
	}
	// fmt.Print("suggested gasPrice = ", gasPrice, "\n")

	toAddress := common.HexToAddress(to)
	tokenAddress := common.HexToAddress(tokenAddr)
	// fmt.Print("toAddress = ", toAddress, "\n")
	// fmt.Print("tokenAddress = ", tokenAddress, "\n")

	transferFnSignature := []byte("transfer(address,uint256)")
	hash := sha3.NewLegacyKeccak256()
	hash.Write(transferFnSignature)
	methodID := hash.Sum(nil)[:4]
	// fmt.Println("\nmethod ID = ", hexutil.Encode(methodID))

	paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
	// fmt.Println("padded Address = ", hexutil.Encode(paddedAddress))

	amount := new(big.Int)
	amount.SetUint64(quantity * tokenDecimal)

	paddedAmount := common.LeftPadBytes(amount.Bytes(), 32)
	// fmt.Println(hexutil.Encode(paddedAmount))
	var data []byte
	data = append(data, methodID...)
	data = append(data, paddedAddress...)
	data = append(data, paddedAmount...)
	gasLimit, err := client.EstimateGas(context.Background(), ethereum.CallMsg{
		To:   &toAddress,
		Data: data,
	})
	if err != nil {
		return TxAnswer{}, errors.New("Error with getting estimating gasLimit: " + err.Error())
	}
	gasLimit = gasLimit * uint64(3)
	// fmt.Println("\ngasLimit = ", gasLimit)

	tx := types.NewTransaction(nonce, tokenAddress, value, uint64(gasLimit), gasPrice, data)

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return TxAnswer{}, errors.New("Error with chainID: " + err.Error())
	}
	// fmt.Println("\nchainID = ", chainID)

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		return TxAnswer{}, errors.New("Error with signin transaction: " + err.Error())
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return TxAnswer{}, errors.New("Error with sending transaction: " + err.Error())
	}

	// fmt.Printf("\ntx sent: %s\n", signedTx.Hash().Hex())
	return TxAnswer{gasPrice, gasLimit, nonce, signedTx.Hash().Hex()}, nil
}

//NewToken creates a connection with ethereum client and makes public key within private.
func NewToken(ethclient *ethclient.Client, key Key) *ERC20 {
	return &ERC20{
		ethclient: ethclient,
		Key:       key,
	}
}

//TxAnswer is a transaction answer...
type TxAnswer struct {
	GasPrice        *big.Int `json:"gasprice,*big.Int"`
	GasLimit        uint64   `json:"gaslimit,uint64"`
	Nonce           uint64   `json:"nonce,uint64"`
	TransactionHash string   `json:"TransactionHash,string"`
}

//SendERC20Token sends token according to the given parameters.
func SendERC20Token(to string, tokenAddr string, quantity uint64, tokenDecimal uint64) (TxAnswer, error) {

	client, err := ethclient.Dial(os.Getenv("RAWURL"))
	// fmt.Println("RAWURL = ", os.Getenv("RAWURL"), "\nKEY = ", os.Getenv("KEY"))
	if err != nil {
		return TxAnswer{}, errors.New("Error with Dialing to ethclient: " + err.Error())
	}
	defer client.Close()

	privateKey, err := crypto.HexToECDSA(os.Getenv("KEY"))
	if err != nil {
		return TxAnswer{}, errors.New("Error with privateKey: " + err.Error())
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return TxAnswer{}, errors.New("Error with getting publicKeyECDSA from private key: ")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return TxAnswer{}, errors.New("Error with nonce: " + err.Error())
	}
	// fmt.Print("nonce = ", nonce, "\n")

	value := big.NewInt(0)
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return TxAnswer{}, errors.New("Error with getting Suggested gasPrice: " + err.Error())
	}
	// fmt.Print("suggested gasPrice = ", gasPrice, "\n")

	toAddress := common.HexToAddress(to)
	tokenAddress := common.HexToAddress(tokenAddr)
	// fmt.Print("toAddress = ", toAddress, "\n")
	// fmt.Print("tokenAddress = ", tokenAddress, "\n")

	transferFnSignature := []byte("transfer(address,uint256)")
	hash := sha3.NewLegacyKeccak256()
	hash.Write(transferFnSignature)
	methodID := hash.Sum(nil)[:4]
	// fmt.Println("\nmethod ID = ", hexutil.Encode(methodID))

	paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
	// fmt.Println("padded Address = ", hexutil.Encode(paddedAddress))

	amount := new(big.Int)
	amount.SetUint64(quantity * tokenDecimal)

	paddedAmount := common.LeftPadBytes(amount.Bytes(), 32)
	// fmt.Println(hexutil.Encode(paddedAmount))
	var data []byte
	data = append(data, methodID...)
	data = append(data, paddedAddress...)
	data = append(data, paddedAmount...)
	gasLimit, err := client.EstimateGas(context.Background(), ethereum.CallMsg{
		To:   &toAddress,
		Data: data,
	})
	if err != nil {
		return TxAnswer{}, errors.New("Error with getting estimating gasLimit: " + err.Error())
	}
	gasLimit = gasLimit * uint64(3)
	// fmt.Println("\ngasLimit = ", gasLimit)

	tx := types.NewTransaction(nonce, tokenAddress, value, uint64(gasLimit), gasPrice, data)

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return TxAnswer{}, errors.New("Error with chainID: " + err.Error())
	}
	// fmt.Println("\nchainID = ", chainID)

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		return TxAnswer{}, errors.New("Error with signin transaction: " + err.Error())
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return TxAnswer{}, errors.New("Error with sending transaction: " + err.Error())
	}

	// fmt.Printf("\ntx sent: %s\n", signedTx.Hash().Hex())
	return TxAnswer{gasPrice, gasLimit, nonce, signedTx.Hash().Hex()}, nil
}

//ERC20Tokens gets a POST request with receiver hash and amount of tokens to send, then it proceeds it to the blockchain
// gets response from it and sends back information to the server in JSON format.
func ERC20Tokens(w http.ResponseWriter, r *http.Request) {
	SetCORSWhitelist(w)
	body, _ := ioutil.ReadAll(r.Body)
	var u MessageGet
	err := json.Unmarshal(body, &u)
	if err != nil {
		formData := MessagePOSTerror{Errors: true, Reason: fmt.Sprint(err)}
		data, err := json.Marshal(formData)
		if err != nil {
			formData := MessagePOSTerror{Errors: true, Reason: fmt.Sprint(err)}
			data, _ = json.Marshal(formData)
			w.Write(data)
			return
		}
		w.Write(data)
		return
	}

	txAnswer, err := tokenTransfer(u.Reciever, u.Amount)
	if err != nil {
		formData := MessagePOSTerror{Errors: true, Reason: fmt.Sprint(err)}
		data, _ := json.Marshal(formData)
		w.Write(data)
		return
	}
	formData := MessagePost{Errors: false, Answer: txAnswer}
	data, err := json.Marshal(formData)
	if err != nil {
		formData := MessagePOSTerror{Errors: true, Reason: fmt.Sprint(err)}
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
