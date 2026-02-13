package bitcoin

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
)

const (
	BitcoinTestnet = "testnet"
	BitcoinMainnet = "mainnet"
)

func getNetworkParams(network string) (*chaincfg.Params, error) {
	switch network {
	case BitcoinMainnet:
		return &chaincfg.MainNetParams, nil
	case BitcoinTestnet:
		return &chaincfg.TestNet4Params, nil
	}
	return nil, fmt.Errorf("invalid network: %s", network)
}
