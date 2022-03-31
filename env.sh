#!/bin/bash

# Server settings
export HTTP_ADDR=8080

# Client settings
export PRIVATE_KEY=
export RPC_URL=https://smartbch.greyh.at/

# KeepAlivePollPeriod is frequency of polling ethernet connection.
export KEEPALIVE_POLL_PERIOD=3


# Transfer settings
export TOKEN_DECIMAL=1000000000000000000
export TOKEN_ADDR=0x714edfC7b5896397905CED2b760B3754Ef8E5e01
export AMOUNT_OF_DECIMALS=18


# Logger settings
export LOG_LEVEL=debug