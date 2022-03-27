package transfer

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/crypto/sha3"
)

//TxAnswer is a transaction answer
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
