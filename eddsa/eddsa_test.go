package eddsa

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/leppaludi/loopring-sig/constants"
	"github.com/leppaludi/loopring-sig/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicKey(t *testing.T) {
	var k PrivateKey
	for i := 0; i < 32; i++ {
		k[i] = byte(i)
	}
	pk := k.Public()
	assert.True(t, pk.X.Cmp(constants.Q) == -1)
	assert.True(t, pk.Y.Cmp(constants.Q) == -1)
}

func TestSignVerifyPoseidon(t *testing.T) {
	var k PrivateKey
	_, err := hex.Decode(k[:],
		[]byte("0001020304050607080900010203040506070809000102030405060708090001"))
	require.Nil(t, err)
	msgBuf, err := hex.DecodeString("00010203040506070809")
	if err != nil {
		panic(err)
	}
	msg := utils.SetBigIntFromLEBytes(new(big.Int), msgBuf)

	pk := k.Public()
	assert.Equal(t,
		"15872208232780880391323496162615626329490592476459343692724793783715106083082",
		pk.X.String())
	assert.Equal(t,
		"3297629380257478865105287016917085619944486593062417198110858086548618481395",
		pk.Y.String())

	sig := k.SignPoseidon(msg)
	assert.Equal(t,
		"10470600857345906672881301454650559478416126535213901415186229677124703353344",
		sig.R8.X.String())
	assert.Equal(t,
		"2330178328697548138350692466726532806450708652360740274697284865429821185419",
		sig.R8.Y.String())
	assert.Equal(t,
		"16556718011482721529331191048420809849166553300187673071306564881097958263618",
		sig.S.String())

	ok := pk.VerifyPoseidon(msg, sig)
	assert.Equal(t, true, ok)

	sigBuf := sig.Compress()
	sig2, err := new(Signature).Decompress(sigBuf)
	assert.Equal(t, nil, err)

	// assert.Equal(t, ""+
	// 	"dfedb4315d3f2eb4de2d3c510d7a987dcab67089c8ace06308827bf5bcbe02a2"+
	// 	"9d043ece562a8f82bfc0adb640c0107a7d3a27c1c7c1a6179a0da73de5c1b203",
	// 	hex.EncodeToString(sigBuf[:]))

	ok = pk.VerifyPoseidon(msg, sig2)
	assert.Equal(t, true, ok)
}

func TestVerifyPoseidon(t *testing.T) {
	msg := utils.NewIntFromString("18907120458743615336946847248227397370763473802204269898187195559525130063203")
	key := utils.NewIntFromString("56869496543825")

	var k PrivateKey
	k = utils.BigIntLEBytes(key)
	pk := k.Public()
	assert.Equal(t,
		"9255092729144892245186624611131828247442112563544941131408300200214096116351",
		pk.X.String())
	assert.Equal(t,
		"8460370541846376796657659750509399834188652251932899797602116208684247832083",
		pk.Y.String())

	x, ok := big.NewInt(0).SetString("12752937249904285198676276090843566060401682639184875784873451302664399892304", 10)
	require.True(t, ok)
	y, ok := big.NewInt(0).SetString("13530361082613950739674235863189737173485045373827356210876301607961589355327", 10)
	require.True(t, ok)
	s, ok := big.NewInt(0).SetString("7616254846080660730932216519770737127037155777726245055053503272117180880572", 10)
	require.True(t, ok)

	sig := &Signature{
		&Point{
			X: x,
			Y: y,
		},
		s,
	}

	ok = pk.VerifyPoseidon(msg, sig)
	assert.Equal(t, true, ok)
}

func TestVerifyPoseidon2(t *testing.T) {
	msg := utils.NewIntFromString("69588426711107115100232500042334179657931174539151555867956034570704220523596")
	msg = msg.Mod(msg, constants.Q)
	key := utils.NewIntFromString("56869496543825")

	var k PrivateKey
	k = utils.BigIntLEBytes(key)
	pk := k.Public()
	assert.Equal(t,
		"9255092729144892245186624611131828247442112563544941131408300200214096116351",
		pk.X.String())
	assert.Equal(t,
		"8460370541846376796657659750509399834188652251932899797602116208684247832083",
		pk.Y.String())

	x, ok := big.NewInt(0).SetString("15162295769440257382486195264681544386788758457719201693385196316384812064800", 10)
	require.True(t, ok)
	y, ok := big.NewInt(0).SetString("2782493627416942909007936076956568507304418921277473381438986134099538816121", 10)
	require.True(t, ok)
	s, ok := big.NewInt(0).SetString("16835165705656063478925976830596286105859651486320548752684160221106715530538", 10)
	require.True(t, ok)

	sig := &Signature{
		&Point{
			X: x,
			Y: y,
		},
		s,
	}

	ok = pk.VerifyPoseidon(msg, sig)
	assert.Equal(t, true, ok)
}
