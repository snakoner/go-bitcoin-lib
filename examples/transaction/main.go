package main

import (
	"context"
	"fmt"

	"github.com/snakoner/go-bitcoin-lib/bitcoin"
)

// cUA3YStCdRkJWKAAXozQ4PTwPB3bY79rJErRE6TE1XEv6FzcJz2j tb1qadvgy7080gdueaxv4p9tysufdxxk8ga40kll2q

// cVNwAb9YW5PFvRSQc6Y8guWQX2JwwjhKooCmM5r1dvzdfZnv1M7M tb1qnacfl6xeczut97mct3yjfu5mc29fnh6rvrg5wx -> to1
// cTXPrNmZXPSd6S332vUL5ZR3UZ2dP7AcR2NJLVxSvBAjUsWVNhCK tb1q4hzf2h8dflwm4r965dmuxp708vgvt4jxw0un96 -> to2
// cPeScL2gDFa2ggmWjQJC3d7FgFmiW2mdDEjZ7XMWmuFxaVm2oV1E tb1q5qal05y83hw070m4eaxscfpyxjdmptmhj648aj -> change
// cQdSj9GnLpLiPJMth8apjr6vsCNfKfBTUKXhPkGtbs36gsNu26a3 tb1qxv7y8kl35u2hfyvnzt9w03l4ypse273lezxymf
// cNKwXHWJQcnr4viFf6oqXZjBZAVsDep7crzmGtocMUZeLCXBmb99 tb1qedddy9c68aa8a0xcp047s3xlalg8w4kfed8y6z
// cTMuYFBxPDh9j9aBWLffLkm2sGA8pumv7f3pEspNwFKJR776BYnT tb1qv4n845euy70tnt89jvd2ffxee72pjaxunlz0qx
// cUiZcgebkTVCCkH9r8yYGv6mnbmGYa4NDVfVjFEv9TTuWPWHxPBB tb1qnjaqdjhzmz9mgck0lrmfx6fxw53he54am0250z
// cN5AaGtyF6w8WihXbQWTXnvTC1p4PLeuhtAc7C66auAGud3S86w5 tb1q6agc4egzryshu8fxxv4rv2dzm546ncak9j63d4
// cQpXwDR246tU1a5Amo5Vcx2yvjwv33And32jtFy7e1A8kMj58nbe tb1q6hkwku6vjx002hc4m4s43t0q9av8n6ud4ujjqn
// cPAKqZDEaV28p9vM8QtH9vT8AmgVJpjmVTezBxiafdJwJ95ASbpP tb1qujdeecnjegxmahkm4tzfdky2ldhy0cgem5jqkz

func main() {
	wif := "cUA3YStCdRkJWKAAXozQ4PTwPB3bY79rJErRE6TE1XEv6FzcJz2j"
	address := "tb1qadvgy7080gdueaxv4p9tysufdxxk8ga40kll2q"

	mempoolClient, err := bitcoin.NewMempoolClient(bitcoin.BitcoinTestnet)
	if err != nil {
		panic(err)
	}
	utxos, err := mempoolClient.FetchUTXOs(context.Background(), address)
	if err != nil {
		panic(err)
	}

	for _, u := range utxos {
		fmt.Printf("- %s:%d amount=%d sat confirmed=%v pkScriptLen=%d\n",
			u.TxID, u.Vout, u.AmountSat, u.Confirmed, len(u.PkScript))
	}

	outputs := []bitcoin.TxOutput{
		{
			Address:   "tb1qnacfl6xeczut97mct3yjfu5mc29fnh6rvrg5wx",
			AmountSat: 10001,
		},
		{
			Address:   "tb1q4hzf2h8dflwm4r965dmuxp708vgvt4jxw0un96",
			AmountSat: 10002,
		},
	}

	rawTx, err := bitcoin.BuildAndSignTx(bitcoin.BitcoinTestnet, wif, "tb1q5qal05y83hw070m4eaxscfpyxjdmptmhj648aj", utxos, outputs, 1000)
	if err != nil {
		panic(err)
	}

	fmt.Println(rawTx)

	txid, err := mempoolClient.BroadcastTx(context.Background(), rawTx)
	if err != nil {
		panic(err)
	}

	fmt.Println(txid)
}
