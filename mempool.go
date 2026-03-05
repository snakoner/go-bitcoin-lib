package bitcoin

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const DustLimitSat = int64(546)

type MempoolClient struct {
	Network string
	BaseURL string
	HTTP    *http.Client
	APIKey  string
}

func getMempoolURL(network string) (string, error) {
	switch network {
	case BitcoinTestnet:
		return "https://mempool.space/testnet/api", nil
	case BitcoinMainnet:
		return "https://mempool.space/api", nil
	default:
		return "", fmt.Errorf("unsupported network: %s", network)
	}
}

func NewMempoolClient(network string, apiKey string) (*MempoolClient, error) {
	baseURL, err := getMempoolURL(network)
	if err != nil {
		return nil, err
	}
	return &MempoolClient{
		Network: network,
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 15 * time.Second},
		APIKey:  apiKey,
	}, nil
}

var (
	TransactionNotFound = fmt.Errorf("tx not found")
)

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
		if resp.StatusCode == http.StatusNotFound {
			return TransactionNotFound
		}
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

type CoinSelection struct {
	Selected  []UTXO
	FeeSat    int64
	ChangeSat int64
}

func (c *MempoolClient) SelectUTXOsForTx(
	ctx context.Context,
	utxos []UTXO,
	outputs []TxOutput,
	changeAddr string,
	mode string,
) (*CoinSelection, error) {
	if len(outputs) == 0 {
		return nil, errors.New("outputs is empty")
	}
	if changeAddr == "" {
		return nil, errors.New("change address is empty")
	}
	if len(utxos) == 0 {
		return nil, errors.New("no utxos provided")
	}

	var totalOut int64
	for _, o := range outputs {
		totalOut += o.AmountSat
	}

	feeRate, err := c.GetFeeRateSatPerVByte(ctx, mode)
	if err != nil {
		return nil, fmt.Errorf("get fee rate: %w", err)
	}

	sorted := make([]UTXO, len(utxos))
	copy(sorted, utxos)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].AmountSat > sorted[j].AmountSat
	})

	numOutputs := len(outputs)

	var selected []UTXO
	var inputSum int64

	for _, u := range sorted {
		selected = append(selected, u)
		inputSum += u.AmountSat

		numInputs := len(selected)

		feeNoChange := feeRate * EstimateTxSizeVBytes(numInputs, numOutputs)
		feeWithChange := feeRate * EstimateTxSizeVBytes(numInputs, numOutputs+1)

		change := inputSum - totalOut - feeWithChange
		if change >= DustLimitSat {
			return &CoinSelection{
				Selected:  selected,
				FeeSat:    feeWithChange,
				ChangeSat: change,
			}, nil
		}

		if inputSum >= totalOut+feeNoChange {
			return &CoinSelection{
				Selected:  selected,
				FeeSat:    inputSum - totalOut,
				ChangeSat: 0,
			}, nil
		}
	}

	return nil, fmt.Errorf("insufficient funds: need at least %d sat, have %d sat", totalOut, inputSum)
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
	mode string,
) (string, error) {
	if len(outputs) == 0 {
		return "", errors.New("outputs is empty")
	}

	utxos, err := c.FetchUTXOs(ctx, fromAddr)
	if err != nil {
		return "", err
	}

	cs, err := c.SelectUTXOsForTx(ctx, utxos, outputs, changeAddr, mode)
	if err != nil {
		return "", err
	}

	rawTx, err := BuildAndSignTx(
		c.Network,
		privWIF,
		changeAddr,
		cs.Selected,
		outputs,
		cs.FeeSat,
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

const (
	FeeFastest  = "fastestFee"
	FeeHalfHour = "halfHourFee"
	FeeHour     = "hourFee"
	FeeEconomy  = "economyFee"
	FeeMinimum  = "minimumFee"
)

func (c *MempoolClient) GetFeeRateSatPerVByte(
	ctx context.Context,
	mode string,
) (int64, error) {
	if mode == "" {
		mode = FeeFastest
	}

	var rec FeeRecommendation
	if err := c.get(ctx, "/v1/fees/recommended", &rec); err != nil {
		return 0, err
	}

	switch mode {
	case FeeFastest:
		return rec.FastestFee, nil
	case FeeHalfHour:
		return rec.HalfHourFee, nil
	case FeeHour:
		return rec.HourFee, nil
	case FeeEconomy:
		return rec.EconomyFee, nil
	case FeeMinimum:
		return rec.MinimumFee, nil
	}

	return 0, fmt.Errorf("invalid fee mode: %s", mode)
}

func (c *MempoolClient) EstimateFeeSat(
	ctx context.Context,
	numInputs int,
	numOutputs int,
	mode string,
) (int64, error) {
	feeRate, err := c.GetFeeRateSatPerVByte(ctx, mode)
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

func (c *MempoolClient) EstimateFeeSatForTx(
	ctx context.Context,
	network string,
	inputs []UTXO,
	outputs []TxOutput,
	changeAddr string,
	mode string,
) (feeSat int64, withChange bool, vbytes int64, err error) {
	feeRate, err := c.GetFeeRateSatPerVByte(ctx, mode)
	if err != nil {
		return 0, false, 0, err
	}

	vbChange, err := EstimateTxVBytes(network, inputs, outputs, true, changeAddr)
	if err != nil {
		return 0, false, 0, err
	}
	feeWithChange := feeRate * vbChange

	var inSum, outSum int64
	for _, in := range inputs {
		inSum += in.AmountSat
	}
	for _, o := range outputs {
		outSum += o.AmountSat
	}

	change := inSum - outSum - feeWithChange
	if change >= DustLimitSat {
		return feeWithChange, true, vbChange, nil
	}

	vbNo, err := EstimateTxVBytes(network, inputs, outputs, false, "")
	if err != nil {
		return 0, false, 0, err
	}
	feeNo := feeRate * vbNo
	return feeNo, false, vbNo, nil
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
	mode string,
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

	feeSat, err := c.EstimateFeeSat(ctx, len(utxos), 1, mode)
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
