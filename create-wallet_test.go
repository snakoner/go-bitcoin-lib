package bitcoin

import (
	"testing"
)

func TestVerifyWIFMatchesAddress(t *testing.T) {
	wif := "cUA3YStCdRkJWKAAXozQ4PTwPB3bY79rJErRE6TE1XEv6FzcJz2j"
	addr := "tb1qadvgy7080gdueaxv4p9tysufdxxk8ga40kll2q"
	network := BitcoinTestnet

	err := VerifyWIFMatchesAddress(wif, addr, network)
	if err != nil {
		t.Errorf("VerifyWIFMatchesAddress failed: %v", err)
	}
}
