package bitcoin

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func SelectUTXOs(utxos []UTXO, target int64) ([]UTXO, int64, error) {
	var selected []UTXO
	var total int64

	for _, u := range utxos {
		selected = append(selected, u)
		total += u.AmountSat
		if total >= target {
			return selected, total, nil
		}
	}
	return nil, 0, fmt.Errorf("insufficient funds: need %d sat", target)
}

type TxOutput struct {
	Address   string
	AmountSat int64
}

func BuildAndSignTx(
	network string,
	privWIF string,
	changeAddr string,
	inputs []UTXO,
	outputs []TxOutput,
	feeSat int64,
) (string, error) {
	params, err := getNetworkParams(network)
	if err != nil {
		return "", err
	}

	wif, err := btcutil.DecodeWIF(privWIF)
	if err != nil {
		return "", err
	}
	if !wif.IsForNet(params) {
		return "", fmt.Errorf("wif is not for %s", network)
	}
	if !wif.CompressPubKey {
		return "", fmt.Errorf("wif is not compressed (required for p2wpkh)")
	}
	privKey := wif.PrivKey

	msgTx := wire.NewMsgTx(2)
	fetcher := txscript.NewMultiPrevOutFetcher(nil)

	var inputSum int64
	for _, in := range inputs {
		h, err := chainhash.NewHashFromStr(in.TxID)
		if err != nil {
			return "", fmt.Errorf("bad txid %s: %w", in.TxID, err)
		}

		op := wire.OutPoint{Hash: *h, Index: in.Vout}
		txIn := wire.NewTxIn(&op, nil, nil)
		msgTx.AddTxIn(txIn)

		fetcher.AddPrevOut(op, &wire.TxOut{
			Value:    in.AmountSat,
			PkScript: in.PkScript,
		})

		inputSum += in.AmountSat
	}

	var outputSum int64
	for _, out := range outputs {
		if out.AmountSat <= 0 {
			return "", fmt.Errorf("invalid output amount: %d", out.AmountSat)
		}

		addr, err := btcutil.DecodeAddress(out.Address, params)
		if err != nil {
			return "", fmt.Errorf("decode address %s: %w", out.Address, err)
		}

		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return "", fmt.Errorf("pay to addr script %s: %w", out.Address, err)
		}

		msgTx.AddTxOut(wire.NewTxOut(out.AmountSat, pkScript))
		outputSum += out.AmountSat
	}

	change := inputSum - outputSum - feeSat
	if change < 0 {
		return "", fmt.Errorf("insufficient funds: in=%d out=%d fee=%d", inputSum, outputSum, feeSat)
	}

	if change >= DustLimitSat {
		addr, err := btcutil.DecodeAddress(changeAddr, params)
		if err != nil {
			return "", fmt.Errorf("decode change address %s: %w", changeAddr, err)
		}
		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return "", fmt.Errorf("pay to change addr script %s: %w", changeAddr, err)
		}
		msgTx.AddTxOut(wire.NewTxOut(change, pkScript))
	} else {
		feeSat += change
		change = 0
	}

	sighashes := txscript.NewTxSigHashes(msgTx, fetcher)

	for i, in := range inputs {
		witness, err := txscript.WitnessSignature(
			msgTx, sighashes, i,
			in.AmountSat,
			in.PkScript,
			txscript.SigHashAll,
			privKey,
			true,
		)
		if err != nil {
			return "", fmt.Errorf("sign input %d: %w", i, err)
		}
		msgTx.TxIn[i].Witness = witness
	}

	var buf bytes.Buffer
	if err := msgTx.Serialize(&buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf.Bytes()), nil
}

func EstimateTxSizeVBytes(
	numInputs int,
	numOutputs int,
) int64 {
	const (
		txOverhead   = 10
		p2wpkhInput  = 68
		p2wpkhOutput = 31
	)

	return int64(
		txOverhead +
			numInputs*p2wpkhInput +
			numOutputs*p2wpkhOutput,
	)
}

func estimateInputVBytes(pkScript []byte) (float64, error) {
	if txscript.IsPayToWitnessPubKeyHash(pkScript) {
		return 68.0, nil
	}
	if txscript.IsPayToTaproot(pkScript) {
		return 57.5, nil
	}
	if txscript.IsPayToPubKeyHash(pkScript) {
		return 148.0, nil
	}
	if txscript.IsPayToScriptHash(pkScript) {
		return 91.0, nil
	}

	return 0, fmt.Errorf("unsupported input script type: %x", pkScript)
}

func estimateOutputVBytes(addr btcutil.Address) (float64, error) {
	switch addr.(type) {
	case *btcutil.AddressWitnessPubKeyHash:
		return 31.0, nil // P2WPKH output
	case *btcutil.AddressTaproot:
		return 43.0, nil // P2TR output
	case *btcutil.AddressPubKeyHash:
		return 34.0, nil // P2PKH output
	case *btcutil.AddressScriptHash:
		return 32.0, nil // P2SH output
	default:
		return 0, fmt.Errorf("unsupported output address type: %T", addr)
	}
}

func EstimateTxVBytes(
	network string,
	inputs []UTXO,
	outputs []TxOutput,
	includeChange bool,
	changeAddr string,
) (int64, error) {
	if len(inputs) == 0 {
		return 0, errors.New("no inputs")
	}
	if len(outputs) == 0 {
		return 0, errors.New("no outputs")
	}

	params, err := getNetworkParams(network)
	if err != nil {
		return 0, err
	}

	hasSegwit := false
	for _, in := range inputs {
		if txscript.IsWitnessProgram(in.PkScript) {
			hasSegwit = true
			break
		}
	}

	overhead := 10.0
	if hasSegwit {
		overhead = 10.5
	}

	vb := overhead

	for _, in := range inputs {
		inVB, err := estimateInputVBytes(in.PkScript)
		if err != nil {
			return 0, err
		}
		vb += inVB
	}

	for _, out := range outputs {
		addr, err := btcutil.DecodeAddress(out.Address, params)
		if err != nil {
			return 0, fmt.Errorf("decode output address %s: %w", out.Address, err)
		}
		outVB, err := estimateOutputVBytes(addr)
		if err != nil {
			return 0, err
		}
		vb += outVB
	}

	if includeChange {
		if changeAddr == "" {
			return 0, errors.New("change address required when includeChange=true")
		}
		addr, err := btcutil.DecodeAddress(changeAddr, params)
		if err != nil {
			return 0, fmt.Errorf("decode change address %s: %w", changeAddr, err)
		}
		outVB, err := estimateOutputVBytes(addr)
		if err != nil {
			return 0, err
		}
		vb += outVB
	}

	return int64(math.Ceil(vb)), nil
}
