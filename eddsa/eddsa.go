package loopring_sig

import (
	"crypto/sha512"
	"math/big"

	"github.com/leppaludi/loopring-sig/ff"
	"github.com/leppaludi/loopring-sig/poseidon"
	"github.com/leppaludi/loopring-sig/utils"
)

// PrivateKey is an EdDSA private key, which is a 32byte buffer.
type PrivateKey [32]byte

// Scalar converts a private key into the scalar value s following the EdDSA
// standard, and using blake-512 hash.
func (k *PrivateKey) Scalar() *PrivKeyScalar {
	s := SkToBigInt(k)
	return NewPrivKeyScalar(s)
}

// SkToBigInt converts a private key into the *big.Int value following the
// EdDSA standard, and using blake-512 hash
func SkToBigInt(k *PrivateKey) *big.Int {
	s := new(big.Int)
	utils.SetBigIntFromLEBytes(s, k[:])
	return s
}

// Public returns the public key corresponding to a private key.
func (k *PrivateKey) Public() *PublicKey {
	return k.Scalar().Public()
}

// BigInt returns the big.Int corresponding to a PrivKeyScalar.
func (s *PrivKeyScalar) BigInt() *big.Int {
	return (*big.Int)(s)
}

// PrivKeyScalar represents the scalar s output of a private key
type PrivKeyScalar big.Int

// NewPrivKeyScalar creates a new PrivKeyScalar from a big.Int
func NewPrivKeyScalar(s *big.Int) *PrivKeyScalar {
	sk := PrivKeyScalar(*s)
	return &sk
}

// Public returns the public key corresponding to the scalar value s of a
// private key.
func (s *PrivKeyScalar) Public() *PublicKey {
	p := NewPoint().Mul((*big.Int)(s), B8)
	pk := PublicKey(*p)
	return &pk
}

// PublicKey represents an EdDSA public key, which is a curve point.
type PublicKey Point

// Point returns the Point corresponding to a PublicKey.
func (pk *PublicKey) Point() *Point {
	return (*Point)(pk)
}

// Mul multiplies the Point q by the scalar s and stores the result in p,
// which is also returned.
func (p *Point) Mul(s *big.Int, q *Point) *Point {
	resProj := &PointProjective{
		X: ff.NewElement().SetZero(),
		Y: ff.NewElement().SetOne(),
		Z: ff.NewElement().SetOne(),
	}
	exp := q.Projective()

	for i := 0; i < s.BitLen(); i++ {
		if s.Bit(i) == 1 {
			resProj.Add(resProj, exp)
		}
		exp = exp.Add(exp, exp)
	}
	p = resProj.Affine()
	return p
}

// Signature represents an EdDSA uncompressed signature.
type Signature struct {
	R8 *Point
	S  *big.Int
}

// SignatureComp represents a compressed EdDSA signature.
type SignatureComp [64]byte

// Compress an EdDSA signature by concatenating the compression of
// the point R8 and the Little-Endian encoding of S.
func (s *Signature) Compress() SignatureComp {
	R8p := s.R8.Compress()
	Sp := utils.BigIntLEBytes(s.S)
	buf := [64]byte{}
	copy(buf[:32], R8p[:])
	copy(buf[32:], Sp[:])
	return SignatureComp(buf)
}

// Decompress a compressed signature into s, and also returns the decompressed
// signature.  Returns error if the Point decompression fails.
func (s *Signature) Decompress(buf [64]byte) (*Signature, error) {
	R8p := [32]byte{}
	copy(R8p[:], buf[:32])
	var err error
	if s.R8, err = NewPoint().Decompress(R8p); err != nil {
		return nil, err
	}
	s.S = utils.SetBigIntFromLEBytes(new(big.Int), buf[32:])
	return s, nil
}

// SignPoseidon signs a message encoded as a big.Int in Zq using blake-512 hash
// for buffer hashing and Poseidon for big.Int hashing.
func (k *PrivateKey) SignPoseidon(msg *big.Int) *Signature {
	n := utils.SetBigIntFromLEBytes(new(big.Int), utils.SwapEndianness(k[:]))

	msgBuf := utils.BigIntLEBytes(msg)
	msgBuf32 := [32]byte{}
	copy(msgBuf32[:], msgBuf[:])

	sum := append(n.Bytes()[:], msgBuf32[:]...)

	hasher := sha512.New()
	hasher.Write(sum)

	r := utils.SetBigIntFromLEBytes(new(big.Int), hasher.Sum(nil)) // r = H(H_{32..63}(k), msg)
	r.Mod(r, SubOrder)

	R8 := NewPoint().Mul(r, B8) // R8 = r * 8 * B
	A := k.Public().Point()

	hmInput := []*big.Int{R8.X, R8.Y, A.X, A.Y, msg}
	hm, err := poseidon.Hash(hmInput) // hm = H1(8*R.x, 8*R.y, A.x, A.y, msg)
	if err != nil {
		panic(err)
	}

	S := SkToBigInt(k)
	S = S.Mul(hm, S)
	S.Add(r, S)
	S.Mod(S, Order) // S = r + hm * 8 * s

	return &Signature{R8: R8, S: S}
}

// VerifyPoseidon verifies the signature of a message encoded as a big.Int in Zq
// using blake-512 hash for buffer hashing and Poseidon for big.Int hashing.
func (pk *PublicKey) VerifyPoseidon(msg *big.Int, sig *Signature) bool {
	hmInput := []*big.Int{sig.R8.X, sig.R8.Y, pk.X, pk.Y, msg}
	hm, err := poseidon.Hash(hmInput) // hm = H1(8*R.x, 8*R.y, A.x, A.y, msg)
	if err != nil {
		return false
	}

	left := NewPoint().Mul(sig.S, B8) // left = s * 8 * B
	r1 := big.NewInt(1)
	r1.Mul(r1, hm)
	right := NewPoint().Mul(r1, pk.Point())
	rightProj := right.Projective()
	rightProj.Add(sig.R8.Projective(), rightProj) // right = 8 * R + 8 * hm * A
	right = rightProj.Affine()
	return (left.X.Cmp(right.X) == 0) && (left.Y.Cmp(right.Y) == 0)
}
