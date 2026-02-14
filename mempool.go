package bitcoin

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type MempoolClient struct {
	Network string
	BaseURL string
	HTTP    *http.Client
}

func getMempoolURL(network string) (string, error) {
	switch network {
	case BitcoinTestnet:
		return "https://mempool.space/testnet4/api", nil
	case BitcoinMainnet:
		return "https://mempool.space/api", nil
	default:
		return "", fmt.Errorf("unsupported network: %s", network)
	}
}

func NewMempoolClient(network string) (*MempoolClient, error) {
	baseURL, err := getMempoolURL(network)
	if err != nil {
		return nil, err
	}
	return &MempoolClient{
		Network: network,
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 15 * time.Second},
	}, nil
}

func (c *MempoolClient) get(ctx context.Context, path string, out any) error {
	if c.BaseURL == "" {
		return errors.New("mempool base url is empty")
	}

	u, err := url.Parse(c.BaseURL + path)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d: %s", resp.StatusCode, string(b))
	}

	return json.Unmarshal(b, out)
}

type AddressUTXO struct {
	TxID   string `json:"txid"`
	Vout   uint32 `json:"vout"`
	Value  int64  `json:"value"`
	Status struct {
		Confirmed   bool  `json:"confirmed"`
		BlockHeight int64 `json:"block_height,omitempty"`
		BlockTime   int64 `json:"block_time,omitempty"`
	} `json:"status"`
}

type Tx struct {
	TxID string `json:"txid"`
	Vout []struct {
		ScriptPubKey string `json:"scriptpubkey"`
		Value        int64  `json:"value"`
	} `json:"vout"`
	Status struct {
		Confirmed   bool  `json:"confirmed"`
		BlockHeight int64 `json:"block_height,omitempty"`
		BlockTime   int64 `json:"block_time,omitempty"`
	} `json:"status"`
}

type UTXO struct {
	TxID      string
	Vout      uint32
	AmountSat int64
	PkScript  []byte
	Confirmed bool
}

func (c *MempoolClient) FetchUTXOs(ctx context.Context, address string) ([]UTXO, error) {
	if address == "" {
		return nil, errors.New("address is empty")
	}

	var apiUtxos []AddressUTXO
	if err := c.get(ctx, "/address/"+url.PathEscape(address)+"/utxo", &apiUtxos); err != nil {
		return nil, err
	}

	txCache := make(map[string]*Tx, 8)

	out := make([]UTXO, 0, len(apiUtxos))
	for _, u := range apiUtxos {
		tx, ok := txCache[u.TxID]
		if !ok {
			var t Tx
			if err := c.get(ctx, "/tx/"+u.TxID, &t); err != nil {
				return nil, fmt.Errorf("fetch tx %s: %w", u.TxID, err)
			}
			tx = &t
			txCache[u.TxID] = tx
		}

		if int(u.Vout) >= len(tx.Vout) {
			return nil, fmt.Errorf("tx %s: vout index %d out of range", u.TxID, u.Vout)
		}

		spkHex := tx.Vout[u.Vout].ScriptPubKey
		pk, err := hex.DecodeString(spkHex)
		if err != nil {
			return nil, fmt.Errorf("tx %s vout %d: bad scriptpubkey hex: %w", u.TxID, u.Vout, err)
		}

		out = append(out, UTXO{
			TxID:      u.TxID,
			Vout:      u.Vout,
			AmountSat: u.Value,
			PkScript:  pk,
			Confirmed: u.Status.Confirmed,
		})
	}

	return out, nil
}

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

	const dustChangeSat = int64(500)
	if change >= dustChangeSat {
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

func (c *MempoolClient) BroadcastTx(ctx context.Context, rawHex string) (string, error) {
	if rawHex == "" {
		return "", errors.New("raw tx is empty")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/tx", strings.NewReader(rawHex))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "text/plain")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("broadcast failed http %d: %s", resp.StatusCode, string(b))
	}

	return strings.TrimSpace(string(b)), nil
}

func (c *MempoolClient) SendTransaction(
	ctx context.Context,
	privWIF string,
	fromAddr string,
	changeAddr string,
	outputs []TxOutput,
) (string, error) {
	if len(outputs) == 0 {
		return "", errors.New("outputs is empty")
	}

	utxos, err := c.FetchUTXOs(ctx, fromAddr)
	if err != nil {
		return "", err
	}

	var totalOut int64
	for _, o := range outputs {
		totalOut += o.AmountSat
	}

	feeSat, err := c.EstimateFeeSat(ctx, len(utxos), len(outputs))
	if err != nil {
		return "", err
	}

	selected, _, err := SelectUTXOs(utxos, totalOut+feeSat)
	if err != nil {
		return "", err
	}

	rawTx, err := BuildAndSignTx(
		c.Network,
		privWIF,
		changeAddr,
		selected,
		outputs,
		feeSat,
	)
	if err != nil {
		return "", err
	}

	return c.BroadcastTx(ctx, rawTx)
}

type FeeRecommendation struct {
	FastestFee  int64 `json:"fastestFee"`
	HalfHourFee int64 `json:"halfHourFee"`
	HourFee     int64 `json:"hourFee"`
	EconomyFee  int64 `json:"economyFee"`
	MinimumFee  int64 `json:"minimumFee"`
}

func (c *MempoolClient) GetFeeRateSatPerVByte(
	ctx context.Context,
) (int64, error) {
	var rec FeeRecommendation
	if err := c.get(ctx, "/v1/fees/recommended", &rec); err != nil {
		return 0, err
	}

	if rec.HourFee > 0 {
		return rec.HourFee, nil
	}

	if rec.MinimumFee > 0 {
		return rec.MinimumFee, nil
	}

	return 0, fmt.Errorf("invalid fee recommendation")
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

func (c *MempoolClient) EstimateFeeSat(
	ctx context.Context,
	numInputs int,
	numOutputs int,
) (int64, error) {

	feeRate, err := c.GetFeeRateSatPerVByte(ctx)
	if err != nil {
		return 0, err
	}

	sizeVBytes := EstimateTxSizeVBytes(numInputs, numOutputs)

	fee := feeRate * sizeVBytes
	if fee <= 0 {
		return 0, fmt.Errorf("invalid fee calculated")
	}

	return fee, nil
}

type TxInfo struct {
	TxID     string `json:"txid"`
	Version  int    `json:"version"`
	Locktime uint32 `json:"locktime"`

	Vin []struct {
		TxID    string `json:"txid"`
		Vout    uint32 `json:"vout"`
		Prevout *struct {
			ScriptPubKey        string `json:"scriptpubkey"`
			ScriptPubKeyType    string `json:"scriptpubkey_type"`
			ScriptPubKeyAddress string `json:"scriptpubkey_address"`
			Value               int64  `json:"value"`
		} `json:"prevout"`
		Sequence uint32 `json:"sequence"`
	} `json:"vin"`

	Vout []struct {
		Value               int64  `json:"value"`
		ScriptPubKey        string `json:"scriptpubkey"`
		ScriptPubKeyType    string `json:"scriptpubkey_type"`
		ScriptPubKeyAddress string `json:"scriptpubkey_address"`
	} `json:"vout"`

	Size   int   `json:"size"`
	Weight int   `json:"weight"`
	Fee    int64 `json:"fee"`

	Status struct {
		Confirmed   bool   `json:"confirmed"`
		BlockHeight int64  `json:"block_height,omitempty"`
		BlockHash   string `json:"block_hash,omitempty"`
		BlockTime   int64  `json:"block_time,omitempty"`
	} `json:"status"`
}

func (c *MempoolClient) GetTransaction(
	ctx context.Context,
	txid string,
) (*TxInfo, error) {

	if txid == "" {
		return nil, errors.New("txid is empty")
	}

	var tx TxInfo
	if err := c.get(ctx, "/tx/"+txid, &tx); err != nil {
		return nil, err
	}

	return &tx, nil
}

func (c *MempoolClient) GetUTXOSatBalance(
	ctx context.Context,
	address string,
	withConfirmed bool,
) (int64, error) {
	utxos, err := c.FetchUTXOs(ctx, address)
	if err != nil {
		return 0, err
	}

	var total int64
	for _, u := range utxos {
		if withConfirmed && !u.Confirmed {
			continue
		}
		total += u.AmountSat
	}

	return total, nil
}

func (c *MempoolClient) SweepTransaction(
	ctx context.Context,
	privWIF string,
	fromAddr string,
	toAddr string,
) (string, error) {
	if fromAddr == "" {
		return "", errors.New("fromAddr is empty")
	}
	if toAddr == "" {
		return "", errors.New("toAddr is empty")
	}

	utxos, err := c.FetchUTXOs(ctx, fromAddr)
	if err != nil {
		return "", err
	}
	if len(utxos) == 0 {
		return "", errors.New("no utxos found for address")
	}

	var totalSat int64
	for _, u := range utxos {
		totalSat += u.AmountSat
	}

	feeSat, err := c.EstimateFeeSat(ctx, len(utxos), 1)
	if err != nil {
		return "", err
	}

	sendSat := totalSat - feeSat
	if sendSat <= 0 {
		return "", fmt.Errorf("balance %d sat is not enough to cover fee %d sat", totalSat, feeSat)
	}

	rawTx, err := BuildAndSignTx(
		c.Network,
		privWIF,
		toAddr,
		utxos,
		[]TxOutput{{Address: toAddr, AmountSat: sendSat}},
		feeSat,
	)
	if err != nil {
		return "", err
	}

	return c.BroadcastTx(ctx, rawTx)
}
