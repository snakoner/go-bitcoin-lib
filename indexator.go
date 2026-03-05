package bitcoin

import (
	"context"
	"fmt"
)

type IndexatorType string

const (
	IndexatorBlockstream IndexatorType = "blockstream"
	IndexatorMempool     IndexatorType = "mempool"
)

type Indexator interface {
	FetchUTXOs(ctx context.Context, address string) ([]UTXO, error)
	GetFeeRateSatPerVByte(ctx context.Context, mode string) (int64, error)
	GetTransaction(ctx context.Context, txid string) (*TxInfo, error)
	GetUTXOSatBalance(ctx context.Context, address string, withConfirmed bool) (int64, error)

	BroadcastTx(ctx context.Context, rawHex string) (string, error)
	SweepTransaction(
		ctx context.Context,
		privWIF string,
		fromAddr string,
		toAddr string,
		mode string,
	) (string, error)
	SendTransaction(
		ctx context.Context,
		privWIF string,
		fromAddr string,
		changeAddr string,
		outputs []TxOutput,
		mode string,
	) (string, error)
}

func NewIndexator(indexator IndexatorType, network string, apiKey string) (Indexator, error) {
	switch indexator {
	case IndexatorBlockstream:
		return NewBlockstreamClient(network, apiKey)
	case IndexatorMempool:
		return NewMempoolClient(network, apiKey)
	default:
		return nil, fmt.Errorf("unsupported indexator: %s", indexator)
	}
}
