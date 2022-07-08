package nft

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetNftData(t *testing.T) {
	nftData, err := GetNftData(
		"0xf70ade3cf6c8d9efdf5c5c826334568ef502e6a0837c4b727cf1a02eb0d1c7ca",
		"0xaf6952cc235343e0cbbb3dcf4c171157ae9b2323",
		"1",
		"0x773674eba65277e47faa2bf4fd2e3fa6c2f01228",
		"0",
	)

	assert.Nil(t, err)
	assert.Equal(t, "0x1ae8f73b227ebc5d6372247ffeed30dd4723e44b9f26e31dc70bcb8dec960011", nftData)

	nftData, err = GetNftData(
		"0x00444a8a4d011553dfe4aed1f4faba56036924a7f07f56f609013e708c0f8c64",
		"0x1234",
		"7",
		"0x7ea605cc180c59f5f642d6ea7a04743cb3d98db4",
		"0",
	)

	assert.Nil(t, err)
	assert.Equal(t, "0x2736b4c2e3a80b5ca68700c2d5225602de036ff4ba61ee1912b271a4a92b0737", nftData)
}
