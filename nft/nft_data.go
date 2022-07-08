package nft

import (
	"math/big"
	"strings"

	"github.com/leppaludi/loopring-sig/poseidon"
)

func GetNftData(
	nftId string,
	tokenAddress string,
	royaltyPercentage string,
	minterAddress string,
	nftType string,
) (string, error) {
	tokenAddressBig := new(big.Int)
	royaltyPercentageBig := new(big.Int)
	minterAddressBig := new(big.Int)
	nftTypeBig := new(big.Int)

	tokenAddressBig.SetString(strings.TrimPrefix(tokenAddress, "0x"), 16)
	royaltyPercentageBig.SetString(royaltyPercentage, 10)
	minterAddressBig.SetString(strings.TrimPrefix(minterAddress, "0x"), 16)
	nftTypeBig.SetString(nftType, 10)

	idNo0x := strings.TrimPrefix(nftId, "0x")

	idNo0xLen := len(idNo0x)
	nftIdLo := new(big.Int)
	nftIdHi := new(big.Int)
	if idNo0xLen > 32 {
		nftIdLo.SetString(idNo0x[idNo0xLen-32:], 16)
		nftIdHi.SetString(idNo0x[:idNo0xLen-32], 16)
	} else {
		nftIdLo.SetString(idNo0x, 16)
	}

	hash, err := poseidon.Hash([]*big.Int{
		minterAddressBig,
		nftTypeBig,
		tokenAddressBig,
		nftIdLo,
		nftIdHi,
		royaltyPercentageBig,
	})
	if err != nil {
		return "", err
	}

	return "0x" + hash.Text(16), nil
}
