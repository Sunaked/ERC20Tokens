package config

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"github.com/kelseyhightower/envconfig"
)

// Config is a config :)
type Config struct {
	PrivateKey   string `envconfig:"PRIVATE_KEY"`
	RPCURL       string `envconfig:"RPC_URL"`
	HTTPAddr     string `envconfig:"HTTP_ADDR"`
	TokenDecimal string `envconfig:"TOKEN_DECIMAL"`
	tokenAddress string `envconfig:"TOKEN_ADDR"`
}

var (
	config Config
	once   sync.Once
)

// Get reads config from environment. Once.
func Get() *Config {
	once.Do(func() {
		err := envconfig.Process("", &config)
		if err != nil {
			log.Fatal(err)
		}
		configBytes, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Configuration:", string(configBytes))
	})
	return &config
}
