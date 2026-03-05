package bitcoin

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type BlockstreamClient struct {
	Network string
	BaseURL string
	HTTP    *http.Client
}

func getBlockstreamURL(network string) (string, error) {
	switch network {
	case BitcoinTestnet:
		return "https://blockstream.info/testnet/api", nil
	case BitcoinMainnet:
		return "https://blockstream.info/api", nil
	default:
		return "", fmt.Errorf("unsupported network: %s", network)
	}
}

func NewBlockstreamClient(network string) (*BlockstreamClient, error) {
	baseURL, err := getBlockstreamURL(network)
	if err != nil {
		return nil, err
	}

	return &BlockstreamClient{
		Network: network,
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 15 * time.Second},
	}, nil
}

func (c *BlockstreamClient) get(ctx context.Context, path string, out any) error {
	if c.BaseURL == "" {
		return errors.New("blockstream base url is empty")
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

func (c *BlockstreamClient) FetchUTXOs(ctx context.Context, address string) ([]UTXO, error) {
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

func (c *BlockstreamClient) BroadcastTx(ctx context.Context, rawHex string) (string, error) {
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

func (c *BlockstreamClient) GetTransaction(ctx context.Context, txid string) (*TxInfo, error) {
	if txid == "" {
		return nil, errors.New("txid is empty")
	}

	var tx TxInfo
	if err := c.get(ctx, "/tx/"+txid, &tx); err != nil {
		return nil, err
	}

	return &tx, nil
}

func (c *BlockstreamClient) GetFeeRateSatPerVByte(ctx context.Context, mode string) (int64, error) {
	if mode == "" {
		mode = FeeFastest
	}

	var estimates map[string]float64
	if err := c.get(ctx, "/fee-estimates", &estimates); err != nil {
		return 0, err
	}

	var targetKey string
	switch mode {
	case FeeFastest:
		targetKey = "1"
	case FeeHalfHour:
		targetKey = "3"
	case FeeHour:
		targetKey = "6"
	case FeeEconomy:
		targetKey = "12"
	case FeeMinimum:
		targetKey = "144"
	default:
		return 0, fmt.Errorf("invalid fee mode: %s", mode)
	}

	if v, ok := estimates[targetKey]; ok && v > 0 {
		return int64(math.Ceil(v)), nil
	}

	var best float64
	for _, v := range estimates {
		if v <= 0 {
			continue
		}
		if best == 0 || v < best {
			best = v
		}
	}
	if best <= 0 {
		return 0, fmt.Errorf("no valid fee estimates")
	}

	return int64(math.Ceil(best)), nil
}

func (c *BlockstreamClient) GetUTXOSatBalance(
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

func (c *BlockstreamClient) EstimateFeeSat(
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

func (c *BlockstreamClient) SelectUTXOsForTx(
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

func (c *BlockstreamClient) SweepTransaction(
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

func (c *BlockstreamClient) SendTransaction(
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
