package psiMagic

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/group"
)

type PsiMage struct {

	// the cyclic group
	cyclicGroup group.Group

	// The Domain Seperation Tag as described in:
	// https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/
	// 2.2.5. Domain separation -- reasonable choice of tag is "QUUX-V<xx>-CS<yy>-<suiteID>" for a fictional application named QUUX
	dst        string
	privKey    group.Scalar // Private Key
	privKeyInv group.Scalar // Private Key inverse
}

func CreateWithNewKey(cyclicgroup group.Group, dst string) (PsiMage, error) {
	if cyclicgroup == nil {
		return PsiMage{}, fmt.Errorf("Group not defined.")
	}

	privKey := cyclicgroup.RandomNonZeroScalar(rand.Reader)
	return CreateFromKey(cyclicgroup, dst, privKey)
}

func CreateFromKey(cyclicgroup group.Group, dst string, pk group.Scalar) (pm PsiMage, err error) {

	pm.cyclicGroup = cyclicgroup
	defer func() {
		if e := recover(); e != nil {
			pm = PsiMage{}
			if e != group.ErrType {
				panic(e)
			} else {
				err = group.ErrType
			}
		}
	}()

	pm.dst = dst

	privKey := cyclicgroup.NewScalar()
	privKey.Set(pk)

	privKeyInv := cyclicgroup.NewScalar()
	privKeyInv.Inv(privKey)

	pm.privKey = privKey
	pm.privKeyInv = privKeyInv

	return pm, nil
}

func (e *PsiMage) Group() group.Group {
	return e.cyclicGroup
}

func (e *PsiMage) GroupName() string {
	return fmt.Sprintf("%s", e.cyclicGroup)
}

func (e *PsiMage) DST() string {
	return e.dst
}

// Encrypt byte array [[H(c)^r]
// Returns the compressed point
func (pm *PsiMage) Encrypt(plain []byte) ([]byte, error) {

	// Encryption
	hp := pm.cyclicGroup.HashToElement(plain, []byte(pm.dst)) // H(c)
	encp := pm.cyclicGroup.NewElement()
	encp.Mul(hp, pm.privKey) // v=H(c)^r

	bencp, err := encp.MarshalBinaryCompress() // Compressed Length less space
	if err != nil {
		return nil, err
	}

	return bencp, nil
}

// Re-encrypts the compressed point [(H(c)^r1)^r2]
// Returns the re-encrypted compressed point
func (pm *PsiMage) ReEncrypt(point []byte) ([]byte, error) {
	// Get point
	encp := pm.cyclicGroup.NewElement()
	err := encp.UnmarshalBinary(point)
	if err != nil {
		return nil, err
	}

	// ReEncrypt the point
	rencp := pm.cyclicGroup.NewElement()
	rencp.Mul(encp, pm.privKey) // w=v^r
	brencp, err := rencp.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	return brencp, nil
}

// Decrypt a compressed point [((H(c)^r1)^r2)^(1/r1)] expects a compressed point
// Returns the decrypted compressed point
func (pm *PsiMage) Decrypt(point []byte) ([]byte, error) {
	// Get point
	encp := pm.cyclicGroup.NewElement()
	err := encp.UnmarshalBinary(point)
	if err != nil {
		return nil, err
	}
	// Decrypt the point
	decp := pm.cyclicGroup.NewElement()
	decp.Mul(encp, pm.privKeyInv) // w^(1/r)
	bdecp, err := decp.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	return bdecp, nil
}
