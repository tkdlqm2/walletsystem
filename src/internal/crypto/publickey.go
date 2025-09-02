package crypto

import (
	"encoding/hex"
	"fmt"
	"hash"

	"errors"
)

// Lengths of hashes and addresses in bytes.
const (
	// HashLength is the expected length of the hash
	HashLength = 32
	// AddressLength is the expected length of the address
	AddressLength = 20
)

type Address [AddressLength]byte
type Hash [HashLength]byte

// common errors
var (
	ErrInvalidAddressFormat   = errors.New("invalid address format")
	ErrInvalidAddressCheckSum = errors.New("invalid address checksum")
	ErrInvalidSignatureFormat = errors.New("invalid signature format")
	ErrInvalidSignature       = errors.New("invalid signature")
	ErrInvalidPublicKey       = errors.New("invalid public key")
	ErrInvalidPublicKeyFormat = errors.New("invalid public key format")
	ErrInsufficientSignature  = errors.New("insufficient signature")
	ErrDuplicatedSignature    = errors.New("duplicated signature")
)

// PublicKeySize is 65 bytes
const PublicKeySize = 65

// PublicKey is the [PublicKeySize]byte with methods
type PublicKey [PublicKeySize]byte

// MarshalJSON is a marshaler function
func (pubkey PublicKey) MarshalJSON() ([]byte, error) {
	return []byte(`"` + pubkey.String() + `"`), nil
}

// UnmarshalJSON is a unmarshaler function
func (pubkey *PublicKey) UnmarshalJSON(bs []byte) error {
	if len(bs) < 3 {
		return ErrInvalidPublicKeyFormat
	}
	if bs[0] != '"' || bs[len(bs)-1] != '"' {
		return ErrInvalidPublicKeyFormat
	}
	v, err := ParsePublicKey(string(bs[1 : len(bs)-1]))
	if err != nil {
		return err
	}
	copy(pubkey[:], v[:])
	return nil
}

// String returns the hex string of the public key
func (pubkey PublicKey) String() string {
	return hex.EncodeToString(pubkey[:])
}

type KeccakState interface {
	hash.Hash
	Read([]byte) (int, error)
}

// String returns the hex string of the public key
func (pubkey PublicKey) Address() Address {
	// h := hash.Hash(pubkey[1:])
	h := Keccak256Hash(pubkey[1:])
	var a Address
	b := h[12:]
	if len(b) > len(a) {
		b = b[len(b)-AddressLength:]
	}
	copy(a[AddressLength-len(b):], b)
	return a
}

// Clone returns the clonend value of it
func (pubkey PublicKey) Clone() PublicKey {
	var cp PublicKey
	copy(cp[:], pubkey[:])
	return cp
}

// ParsePublicKey parse the public hash from the string
func ParsePublicKey(str string) (PublicKey, error) {
	if len(str) != PublicKeySize*2 {
		return PublicKey{}, ErrInvalidPublicKeyFormat
	}
	bs, err := hex.DecodeString(str)
	if err != nil {
		return PublicKey{}, err
	}
	var pubkey PublicKey
	copy(pubkey[:], bs)
	return pubkey, nil
}

// MustParsePublicKey panic when error occurred
func MustParsePublicKey(str string) PublicKey {
	pubkey, err := ParsePublicKey(str)
	if err != nil {
		fmt.Println("MustParsePublicKey error", err)
		panic(err)
	}
	return pubkey
}
