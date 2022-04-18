package transfer

import (
	"bytes"
	"container/list"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"rfc20TokenTransfer/config"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

//CorsWhiteList is a list of addresses that are allowed to the CORS.
var CorsWhiteList = []string{strings.Join([]string{"http://localhost:", os.Getenv("HTTP_ADDR"), "/transferERC20Tokens/"}, "")}

//MessageGet get is a message FROM the server with POST parameters.
type MessageGet struct {
	Reciever string `json:"reciever"`
	Amount   string `json:"amount"`
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
	public  *ecdsa.PublicKey
	Private *ecdsa.PrivateKey
}

//ERC20 represents a token that implements http.Handler interface
type ERC20 struct {
	ethclient *ethclient.Client
	Key       Key
	Queue     *list.List
	nonce     uint64
}

//GetETHClient  creates ethclient.Client connection
func GetETHClient() (*ethclient.Client, error) {
	cfg := config.Get()
	client, err := ethclient.Dial(cfg.RPCURL)
	if err != nil {
		return nil, fmt.Errorf("Error with ethclient: %v", err)
	}
	return client, nil
}

//ServeQueue takes values from queue and makes transaction in the ethereum network
func (e *ERC20) ServeQueue() {
	for {
		queValue := e.Queue.Front()
		if queValue == nil {
			continue
		}
		rawTxBytes, err := hex.DecodeString(fmt.Sprint(queValue.Value))
		if err != nil {
			formData := MessagePOSTerror{Errors: true, Reason: err.Error()}
			data, _ := json.Marshal(formData)
			buf := bytes.NewBuffer(data)
			http.Post("localhost:"+os.Getenv("HTTP_ADDR")+"/transferERC20Tokens/", "application/json", buf)
		}

		tx := new(types.Transaction)
		rlp.DecodeBytes(rawTxBytes, &tx)
		err = e.ethclient.SendTransaction(context.Background(), tx)

		// fmt.Println("SERVE Queue Remove transaction from queue (nonce, hash) = (", tx.Nonce(), ", ", tx.Hash(), ")")
		e.Queue.Remove(queValue)

	}
}

// KeepAlive is polling ethclient.Client connection and if connections is lost, it will reconnect.
func (e *ERC20) KeepAlive() {
	for {
		cfg := config.Get()
		fromAddress := crypto.PubkeyToAddress(*e.Key.public)
		var err error

		time.Sleep(time.Second * time.Duration(cfg.KeepAlivePollPeriod))
		lostConnect := false

		if e.ethclient == nil {
			lostConnect = true
		} else if _, err := e.ethclient.PendingNonceAt(context.Background(), fromAddress); err != nil {
			lostConnect = true
		}
		if !lostConnect {
			continue
		}
		log.Print("[ERC20.ethereumClient] Lost Ethereum connection. Restoring...")
		e.ethclient, err = GetETHClient()
		if err != nil {
			log.Print(err)
			continue
		}
	}
}

//NewToken creates a connection with ethereum client and makes public key within private.
func NewToken() (*ERC20, error) {
	cfg := config.Get()
	client, err := GetETHClient()
	if err != nil {
		return nil, errors.New("Something went wrong with getting ethereum client" + err.Error())
	}
	privateKey, err := crypto.HexToECDSA(cfg.PrivateKey)
	if err != nil {
		return nil, errors.New("Error with privateKey: " + err.Error())
	}
	publicKey := privateKey.Public()
	key, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Something went wrong with public key")
	}
	fromAddress := crypto.PubkeyToAddress(*key)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return nil, errors.New("Error with nonce: " + err.Error())
	}
	return &ERC20{
		ethclient: client,
		Queue:     list.New(),
		nonce:     nonce,
		Key: Key{
			public:  publicKey.(*ecdsa.PublicKey),
			Private: privateKey,
		},
	}, nil
}

//TxAnswer is a transaction answer...
type TxAnswer struct {
	GasPrice        *big.Int `json:"gasprice,*big.Int"`
	GasLimit        uint64   `json:"gaslimit,uint64"`
	Nonce           uint64   `json:"nonce,uint64"`
	TransactionHash string   `json:"TransactionHash,string"`
}

//PostError takes error and http.ResponseWriter and writes error to http.
func PostError(w http.ResponseWriter, err error) {
	formData := MessagePOSTerror{Errors: true, Reason: err.Error()}
	data, _ := json.Marshal(formData)
	w.Write(data)
}

//GetAmountOfDecimals returns zeros in quantity of env variable AMOUNT_OF_DECIMALS in string format.
func GetAmountOfDecimals(num string) string {
	// fmt.Println("================GetAmountOfDecimals================")
	cfg := config.Get()
	// fmt.Println("num = ", num)
	numbers := strings.Split(num, ".") // разделили число на "до" и "после" запятой
	// fmt.Println("len(numbers) = ", len(numbers))

	if len(numbers) > 1 {
		// fmt.Println("\n=====There is a Dot")
		firstHalf := numbers[0]
		secondHalf := numbers[1]
		// fmt.Println("firstHalf = ", firstHalf)
		// fmt.Println("secondHalf = ", secondHalf)
		var count int

		if firstHalf == "0" {
			// fmt.Println("\n=====Before dot only thero")
			firstHalf = ""
			for _, letter := range secondHalf {
				// fmt.Println("letter = ", string(letter))
				if letter == '0' {
					// fmt.Println("letter equals 0")
					count++
				} else {
					// fmt.Println("sequence of theros ends")
					break
				}
			}
			var tmp string = secondHalf[count:]
			// fmt.Println("tmp = ", tmp)
			// fmt.Println("count = ", count)
			secondHalf = fmt.Sprint(tmp, strings.Repeat("0", cfg.AmountOfDecimals-len([]rune(tmp))-count))
		} else {
			// fmt.Println("\n=====firstHalf not equals to 0")
			amountOfTherosToAdd := cfg.AmountOfDecimals - len([]rune(secondHalf))
			var out = fmt.Sprint(numbers[0], numbers[1], strings.Repeat("0", amountOfTherosToAdd))
			// fmt.Println("out = ", out)
			return out
		}

		// fmt.Println("\n=====second half = ", secondHalf)
		var out string = fmt.Sprint(strings.Join([]string{firstHalf, secondHalf}, ""))
		// fmt.Println("out = ", out)
		return out
	}
	// fmt.Println("\nLast part")
	var out string = fmt.Sprint(numbers[0], strings.Repeat("0", cfg.AmountOfDecimals-len(numbers[0])+2))
	// fmt.Println("out = ", out)
	return out

}

func getMethodID() (methodID []byte) {
	transferFnSignature := []byte("transfer(address,uint256)")
	hash := sha3.NewLegacyKeccak256()
	hash.Write(transferFnSignature)
	methodID = hash.Sum(nil)[:4]
	return
}

//ServeHTTP sends raw transaction to the queue
func (e ERC20) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	SetCORSWhitelist(w)

	// fmt.Print("nonce = ", nonce, "\n")
	///////// Getting requests ////////////////////
	body, _ := ioutil.ReadAll(r.Body)
	var u MessageGet
	err := json.Unmarshal(body, &u)
	if err != nil {
		formData := MessagePOSTerror{Errors: true, Reason: fmt.Sprint(err)}
		data, err := json.Marshal(formData)
		if err != nil {
			PostError(w, err)
			return
		}
		w.Write(data)
		return
	}

	///////////////// Making transaction from request /////////////////////
	rawTxHex, err := makeTransaction(e, u)

	//////////////////Sending transaction to the QUEUE ////////////////////////
	// log.Println("SERVE HTTP Push transaction to queue (nonce, hash) = (", tx.Nonce(), ", ", signedTx.Hash().Hex(), ")")
	e.Queue.PushBack(rawTxHex)

	/////////////////// Sendign response to the server /////////////////////////////
	rawTxBytes, err := hex.DecodeString(rawTxHex)
	if err != nil {
		PostError(w, err)
		return
	}

	tx := new(types.Transaction)
	rlp.DecodeBytes(rawTxBytes, &tx)

	txAnswer := TxAnswer{tx.GasPrice(), tx.Gas(), tx.Nonce(), tx.Hash().Hex()}
	err = sendReponse(w, txAnswer)
	if err != nil {
		PostError(w, err)
	}
}

var count uint64
var mu sync.Mutex

func makeTransaction(e ERC20, u MessageGet) (string, error) {
	cfg := config.Get()

	nonce := e.nonce
	mu.Lock()
	nonce += count
	count++
	mu.Unlock()

	toAddress := common.HexToAddress(u.Reciever)
	tokenAddress := common.HexToAddress(cfg.TokenAddress)

	methodID := getMethodID()

	paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)

	amount := new(big.Int)
	amt := GetAmountOfDecimals(u.Amount)
	amount.SetString(amt, 10)

	paddedAmount := common.LeftPadBytes(amount.Bytes(), 32)

	var data []byte
	data = append(data, methodID...)
	data = append(data, paddedAddress...)
	data = append(data, paddedAmount...)

	gasLimit, err := e.ethclient.EstimateGas(context.Background(), ethereum.CallMsg{
		To:   &toAddress,
		Data: data,
	})
	if err != nil {
		// PostError(w, errors.New("Error with getting estimating gasLimit: "+err.Error()))
		return "", errors.New("Error with getting estimating gasLimit: " + err.Error())
	}

	gasLimit = gasLimit * uint64(3)
	// fmt.Println("Making new transaction with parameters:")
	// fmt.Println("Nonce = ", nonce)
	gasPrice, err := e.ethclient.SuggestGasPrice(context.Background())
	if err != nil {
		// PostError(w, errors.New("Error with getting Suggested gasPrice: "+err.Error()))
		return "", errors.New("Error with getting Suggested gasPrice: " + err.Error())
	}
	tx := types.NewTransaction(nonce, tokenAddress, big.NewInt(0), uint64(gasLimit), gasPrice, data)

	chainID, err := e.ethclient.NetworkID(context.Background())
	if err != nil {
		// PostError(w, errors.New("Error with chainID: "+err.Error()))
		return "", errors.New("Error with chainID: " + err.Error())
	}
	// fmt.Println("\nchainID = ", chainID)

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), e.Key.Private)
	if err != nil {
		// PostError(w, errors.New("Error with sign the transaction: "+err.Error()))
		return "", errors.New("Error with sign the transaction: " + err.Error())
	}

	buf := bytes.NewBuffer(make([]byte, 0, 1024))

	ts := types.Transactions{signedTx}
	ts.EncodeIndex(0, buf)
	rawTxHex := hex.EncodeToString(buf.Bytes())
	return rawTxHex, nil
}

func sendReponse(w http.ResponseWriter, txAnswer TxAnswer) error {
	formData := MessagePost{Errors: false, Answer: txAnswer}
	data, err := json.Marshal(formData)
	if err != nil {
		return err
	}
	w.Write(data)
	return nil
}
