package bitcoin

import (
	"fmt"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
)

type KeyPair struct {
	PrivateKey string // WIF
	Address    string // bech32 (bc1... / tb1...)
}

func GenerateBitcoinAddress(network string) (KeyPair, error) {
	networkParams, err := getNetworkParams(network)
	if err != nil {
		return KeyPair{}, err
	}

	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		return KeyPair{}, fmt.Errorf("new private key: %w", err)
	}

	wif, err := btcutil.NewWIF(privateKey, networkParams, true)
	if err != nil {
		return KeyPair{}, fmt.Errorf("new wif: %w", err)
	}

	publicKey := privateKey.PubKey()
	pubKeyHash := btcutil.Hash160(publicKey.SerializeCompressed())

	segwitAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, networkParams)
	if err != nil {
		return KeyPair{}, fmt.Errorf("new segwit addr: %w", err)
	}

	return KeyPair{
		PrivateKey: wif.String(),
		Address:    segwitAddr.EncodeAddress(),
	}, nil
}

func VerifyWIF(wifStr string, network string) (*btcutil.WIF, error) {
	wif, err := btcutil.DecodeWIF(wifStr)
	if err != nil {
		return nil, fmt.Errorf("invalid WIF: %w", err)
	}

	params, err := getNetworkParams(network)
	if err != nil {
		return nil, err
	}

	if !wif.IsForNet(params) {
		return nil, fmt.Errorf("WIF is not for %s", network)
	}

	if !wif.CompressPubKey {
		return nil, fmt.Errorf("WIF is not compressed (SegWit requires compressed keys)")
	}

	return wif, nil
}

func VerifyWIFMatchesAddress(wifStr, expectedAddr, network string) error {
	wif, err := VerifyWIF(wifStr, network)
	if err != nil {
		return err
	}

	params, err := getNetworkParams(network)
	if err != nil {
		return err
	}

	pubKey := wif.PrivKey.PubKey()
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())

	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, params)
	if err != nil {
		return err
	}

	if addr.EncodeAddress() != expectedAddr {
		return fmt.Errorf("WIF does not match address")
	}
	return nil
}
