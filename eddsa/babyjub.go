package eddsa

import (
	"fmt"
	"math/big"

	"github.com/leppaludi/loopring-sig/constants"
	"github.com/leppaludi/loopring-sig/ff"
	"github.com/leppaludi/loopring-sig/utils"
)

// A is one of the babyjub constants.
var A *big.Int

// Aff is A value in *ff.Element representation
var Aff *ff.Element

// D is one of the babyjub constants.
var D *big.Int

// Dff is D value in *ff.Element representation
var Dff *ff.Element

// B8 is a base point of the babyjub multiplied by 8 to make it a base point of
// the subgroup in the curve.
var B8 *Point

// Order of the babyjub curve.
var Order *big.Int

// SubOrder is the order of the subgroup of the babyjub curve that contains the
// points that we use.
var SubOrder *big.Int

// Cofactor.
var C *big.Int

// L*B = 0, and (2^C)*L == #E
var L *big.Int

// init initializes global numbers and the subgroup base.
func init() {
	A = utils.NewIntFromString("168700")
	D = utils.NewIntFromString("168696")
	Dff = ff.NewElement().SetBigInt(D)
	Aff = ff.NewElement().SetBigInt(A)

	B8 = NewPoint()
	B8.X = utils.NewIntFromString(
		"16540640123574156134436876038791482806971768689494387082833631921987005038935")
	B8.Y = utils.NewIntFromString(
		"20819045374670962167435360035096875258406992893633759881276124905556507972311")

	Order = utils.NewIntFromString(
		"21888242871839275222246405745257275088614511777268538073601725287587578984328")
	SubOrder = new(big.Int).Rsh(Order, 3) //nolint:gomnd

	C = new(big.Int).SetInt64(8)

	L = new(big.Int).Set(Order)
	L = L.Div(L, C)
}

// PointProjective is the Point representation in projective coordinates
type PointProjective struct {
	X *ff.Element
	Y *ff.Element
	Z *ff.Element
}

// NewPointProjective creates a new Point in projective coordinates.
func NewPointProjective() *PointProjective {
	return &PointProjective{X: ff.NewElement().SetZero(),
		Y: ff.NewElement().SetOne(), Z: ff.NewElement().SetOne()}
}

// Add computes the addition of two points in projective coordinates
// representation
func (p *PointProjective) Add(q *PointProjective, o *PointProjective) *PointProjective {
	// add-2008-bbjlp
	// https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#doubling-dbl-2008-bbjlp
	a := ff.NewElement().Mul(q.Z, o.Z)
	b := ff.NewElement().Square(a)
	c := ff.NewElement().Mul(q.X, o.X)
	d := ff.NewElement().Mul(q.Y, o.Y)
	e := ff.NewElement().Mul(Dff, c)
	e.Mul(e, d)
	f := ff.NewElement().Sub(b, e)
	g := ff.NewElement().Add(b, e)
	x1y1 := ff.NewElement().Add(q.X, q.Y)
	x2y2 := ff.NewElement().Add(o.X, o.Y)
	x3 := ff.NewElement().Mul(x1y1, x2y2)
	x3.Sub(x3, c)
	x3.Sub(x3, d)
	x3.Mul(x3, a)
	x3.Mul(x3, f)
	ac := ff.NewElement().Mul(Aff, c)
	y3 := ff.NewElement().Sub(d, ac)
	y3.Mul(y3, a)
	y3.Mul(y3, g)
	z3 := ff.NewElement().Mul(f, g)

	p.X = x3
	p.Y = y3
	p.Z = z3
	return p
}

// Affine returns the Point from the projective representation
func (p *PointProjective) Affine() *Point {
	if p.Z.Equal(ff.NewElement().SetZero()) {
		return &Point{
			X: big.NewInt(0),
			Y: big.NewInt(0),
		}
	}
	zinv := ff.NewElement().Inverse(p.Z)
	x := ff.NewElement().Mul(p.X, zinv)

	y := ff.NewElement().Mul(p.Y, zinv)
	xBig := big.NewInt(0)
	x.ToBigIntRegular(xBig)
	yBig := big.NewInt(0)
	y.ToBigIntRegular(yBig)
	return &Point{
		X: xBig,
		Y: yBig,
	}
}

// Point represents a point of the babyjub curve.
type Point struct {
	X *big.Int
	Y *big.Int
}

// NewPoint creates a new Point.
func NewPoint() *Point {
	return &Point{X: big.NewInt(0), Y: big.NewInt(1)}
}

// PointCoordSign returns the sign of the curve point coordinate.  It returns
// false if the sign is positive and false if the sign is negative.
func PointCoordSign(c *big.Int) bool {
	return c.Cmp(new(big.Int).Rsh(constants.Q, 1)) == 1
}

// PackSignY packs the given sign and the coordinate Y of a point into a 32
// byte array. This method does not check that the values belong to a valid
// Point in the curve.
func PackSignY(sign bool, y *big.Int) [32]byte {
	leBuf := utils.BigIntLEBytes(y)
	if sign {
		leBuf[31] = leBuf[31] | 0x80 //nolint:gomnd
	}
	return leBuf
}

// UnpackSignY returns the sign and coordinate Y from a given compressed point.
// This method does not check that the Point belongs to the BabyJubJub curve,
// thus does not return error in such case. This method is intended to obtain
// the sign and the Y coordinate without checking if the point belongs to the
// curve, if the objective is to uncompress a point, Decompress method should
// be used instead.
func UnpackSignY(leBuf [32]byte) (bool, *big.Int) {
	sign := false
	y := big.NewInt(0)
	if (leBuf[31] & 0x80) != 0x00 { //nolint:gomnd
		sign = true
		leBuf[31] = leBuf[31] & 0x7F //nolint:gomnd
	}
	utils.SetBigIntFromLEBytes(y, leBuf[:])
	return sign, y
}

// Compress the point into a 32 byte array that contains the y coordinate in
// little endian and the sign of the x coordinate.
func (p *Point) Compress() [32]byte {
	sign := PointCoordSign(p.X)
	return PackSignY(sign, p.Y)
}

// Projective returns a PointProjective from the Point
func (p *Point) Projective() *PointProjective {
	return &PointProjective{
		X: ff.NewElement().SetBigInt(p.X),
		Y: ff.NewElement().SetBigInt(p.Y),
		Z: ff.NewElement().SetOne(),
	}
}

// Decompress a compressed Point into p, and also returns the decompressed
// Point.  Returns error if the compressed Point is invalid.
func (p *Point) Decompress(leBuf [32]byte) (*Point, error) {
	var sign bool
	sign, p.Y = UnpackSignY(leBuf)
	return PointFromSignAndY(sign, p.Y)
}

// PointFromSignAndY returns a Point from a Sign and the Y coordinate
func PointFromSignAndY(sign bool, y *big.Int) (*Point, error) {
	var p Point
	p.X = big.NewInt(0)
	p.Y = y
	if p.Y.Cmp(constants.Q) >= 0 {
		return nil, fmt.Errorf("p.y >= Q")
	}

	y2 := new(big.Int).Mul(p.Y, p.Y)
	y2.Mod(y2, constants.Q)
	xa := big.NewInt(1)
	xa.Sub(xa, y2) // xa == 1 - y^2

	xb := new(big.Int).Mul(D, y2)
	xb.Mod(xb, constants.Q)
	xb.Sub(A, xb) // xb = A - d * y^2

	if xb.Cmp(big.NewInt(0)) == 0 {
		return nil, fmt.Errorf("division by 0")
	}
	xb.ModInverse(xb, constants.Q)
	p.X.Mul(xa, xb) // xa / xb
	p.X.Mod(p.X, constants.Q)
	noSqrt := p.X.ModSqrt(p.X, constants.Q)
	if noSqrt == nil {
		return nil, fmt.Errorf("x is not a square mod q")
	}
	if (sign && !PointCoordSign(p.X)) || (!sign && PointCoordSign(p.X)) {
		p.X.Mul(p.X, constants.MinusOne)
	}
	p.X.Mod(p.X, constants.Q)

	return &p, nil
}
