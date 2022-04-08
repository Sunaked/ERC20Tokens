#!/bin/bash

# Server settings
export HTTP_ADDR=8080

# Client settings
export PRIVATE_KEY=fa4e820f857deb7e19eaa23b16d968e719bf69a2bbea03330f107636b1ef3c01
export RPC_URL=https://smartbch.greyh.at/

# KeepAlivePollPeriod is frequency of polling ethernet connection.
export KEEPALIVE_POLL_PERIOD=3


# Transfer settings
export TOKEN_ADDR=0x714edfC7b5896397905CED2b760B3754Ef8E5e01
export AMOUNT_OF_DECIMALS=18
# -1 is stand for input precision
export FLOAT_PRECISION=6


# Logger settings
# export LOG_LEVEL=debug