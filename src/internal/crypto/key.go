package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/acecasino/account_manage/internal/cloud"
	"github.com/acecasino/account_manage/pkg/logger"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

// MemoryKey is the in-memory crypto key
type MemoryKey struct {
	PrivKey *ecdsa.PrivateKey
	pubkey  PublicKey
}

// NewMemoryKeyFromString parse memory key by the hex string
func NewMemoryKeyFromString(sk string) (*MemoryKey, error) {
	ac := &MemoryKey{
		PrivKey: &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: secp256k1.S256(),
			},
			D: new(big.Int),
		},
	}
	ac.PrivKey.D.SetString(sk, 16)
	ac.PrivKey.PublicKey.X, ac.PrivKey.PublicKey.Y = ac.PrivKey.Curve.ScalarBaseMult(ac.PrivKey.D.Bytes())
	if err := ac.calcPubkey(); err != nil {
		fmt.Println(err.Error())
		return nil, err
	}
	return ac, nil
}

// NewMemoryKeyFromString parse memory key by the hex string
func NewMemoryKeyFromString2(sk string) (*MemoryKey, error) {
	ac := &MemoryKey{
		PrivKey: &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: secp256k1.S256(),
			},
			D: new(big.Int),
		},
	}
	ac.PrivKey.D.SetString(sk, 16)
	ac.PrivKey.PublicKey.X, ac.PrivKey.PublicKey.Y = ac.PrivKey.Curve.ScalarBaseMult(ac.PrivKey.D.Bytes())
	if err := ac.calcPubkey(); err != nil {
		fmt.Println(err.Error())
		return nil, err
	}
	return ac, nil
}

func GeneratePrivateKey(email string) (string, error) {
	log := logger.GetLogger().WithField("email : ", (email))

	// 환경변수 검증
	seed := os.Getenv("SEED")
	if seed == "" {
		return "", errors.New("SEED environment variable not set")
	}

	salt := os.Getenv("SALT")
	if salt == "" {
		return "", errors.New("SALT environment variable not set")
	}

	// 1. 안전한 키 생성을 위한 입력 준비
	derivationInput := prepareDerivationInput(email, seed, salt)

	// 2. PBKDF2를 사용한 키 파생 (더 안전한 방법)
	derivedKey := pbkdf2.Key([]byte(derivationInput), []byte(salt), 100000, 32, sha256.New)

	// 3. 추가 엔트로피를 위한 해싱
	finalHash := sha256.Sum256(derivedKey)

	// 4. Private Key 생성 시도 (재시도 로직 개선)
	privateKey, err := generatePrivateKeyWithRetry(finalHash[:])
	if err != nil {
		log.WithError(err).Error("Failed to generate private key")
		return "", err
	}

	return privateKey, nil
}

// 개선된 Private Key 생성 재시도 로직
func generatePrivateKeyWithRetry(keyMaterial []byte) (string, error) {
	const maxRetries = 10

	for attempt := 0; attempt < maxRetries; attempt++ {
		// 시도마다 약간씩 다른 입력 사용
		input := append(keyMaterial, byte(attempt))
		hash := sha256.Sum256(input)

		mk, err := NewMemoryKeyFromBytes(hash[:])
		if err == nil {
			// 성공적으로 생성됨
			return hex.EncodeToString(mk.PrivKey.D.Bytes()), nil
		}

		// 로그 남기기 (너무 자주 남기지 않도록)
		if attempt%3 == 0 {
			logger.GetLogger().WithField("attempt", attempt).Debug("Private key generation attempt failed")
		}
	}

	return "", errors.New("failed to generate valid private key after maximum retries")
}

// 이메일과 추가 파라미터로 파생 입력 준비
func prepareDerivationInput(email, seed, salt string) string {
	// 이메일을 정규화 (소문자, 공백 제거)
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))

	// 타임스탬프 기반 고정값 (일별 고정, 선택사항)
	// timeComponent := strconv.FormatInt(time.Now().Unix()/(24*3600), 10) // 일별 변경

	// 조합하여 파생 입력 생성
	return fmt.Sprintf("wallet_derivation_%s_%s_%s",
		normalizedEmail, seed, salt)
}

// NewMemoryKeyFromBytes parse memory key by the byte array
func NewMemoryKeyFromBytes(pk []byte) (*MemoryKey, error) {
	ac := &MemoryKey{
		PrivKey: &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: secp256k1.S256(),
			},
			D: new(big.Int),
		},
	}
	ac.PrivKey.D.SetBytes(pk)
	ac.PrivKey.PublicKey.X, ac.PrivKey.PublicKey.Y = ac.PrivKey.Curve.ScalarBaseMult(ac.PrivKey.D.Bytes())
	if err := ac.calcPubkey(); err != nil {
		fmt.Println(err.Error())
		return nil, err
	}
	return ac, nil
}

// Clear removes private key bytes data
func (ac *MemoryKey) Clear() {
	ac.PrivKey.D.SetBytes([]byte{0})
	ac.PrivKey.X.SetBytes([]byte{0})
	ac.PrivKey.Y.SetBytes([]byte{0})
}

func (ac *MemoryKey) calcPubkey() error {
	bs := elliptic.Marshal(ac.PrivKey.PublicKey.Curve, ac.PrivKey.PublicKey.X, ac.PrivKey.PublicKey.Y)
	copy(ac.pubkey[:], bs[:])
	return nil
}

// PublicKey returns the public key of the private key
func (ac *MemoryKey) PublicKey() PublicKey {
	return ac.pubkey
}

// PrivateKey returns *ecdsa.PrivateKey  of the private key
func (ac *MemoryKey) PrivateKey() *ecdsa.PrivateKey {
	return ac.PrivKey
}

// Bytes returns the byte array of the key
func (ac *MemoryKey) Bytes() []byte {
	return ac.PrivKey.D.Bytes()
}

// Keccak256Hash calculates and returns the Keccak256 hash of the input data,
// converting it to an internal Hash data structure.
func Keccak256Hash(data ...[]byte) (h Hash) {
	d := sha3.NewLegacyKeccak256().(KeccakState)
	for _, b := range data {
		d.Write(b)
	}
	d.Read(h[:])
	return h
}

// Hex returns an EIP55-compliant hex string representation of the address.
func (a Address) String() string {
	return string(a.checksumHex())
}

func (a Address) hex() []byte {
	var buf [len(a)*2 + 2]byte
	copy(buf[:2], "0x")
	hex.Encode(buf[2:], a[:])
	return buf[:]
}

func (a *Address) checksumHex() []byte {
	buf := a.hex()

	// compute checksum
	sha := sha3.NewLegacyKeccak256()
	sha.Write(buf[2:])
	hash := sha.Sum(nil)
	for i := 2; i < len(buf); i++ {
		hashByte := hash[(i-2)/2]
		if i%2 == 0 {
			hashByte = hashByte >> 4
		} else {
			hashByte &= 0xf
		}
		if buf[i] > '9' && hashByte > 7 {
			buf[i] -= 32
		}
	}
	return buf[:]
}

// GetPrivateKey는 이메일을 사용하여 개인키를 가져옵니다
func GetPrivateKey(email string) (string, error) {
	// 데이터베이스에서 암호화된 private key를 조회하고 복호화해서 반환
	// 이 함수는 데이터베이스 연결이 필요하므로 호출부에서 처리하도록 변경
	return "", fmt.Errorf("GetPrivateKey function needs database connection - use GetPrivateKeyFromDB instead")
}

// GetAdminPrivateKey는 관리자 개인키를 가져옵니다
func GetAdminPrivateKey(ctx context.Context) (string, error) {
	// AWS 클라이언트를 통해 관리자 개인키를 가져옵니다
	walletService, err := cloud.GetWalletDecryptService(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get wallet decrypt service: %w", err)
	}

	// 관리자 지갑 시크릿 조회 및 복호화
	// secretID와 keyAlias는 환경변수나 설정에서 가져와야 합니다
	secretID := os.Getenv("SECRETID")
	if secretID == "" {
		return "", errors.New("SECRETID environment variable not set")
	}

	keyAlias := os.Getenv("KEYALIAS")
	if keyAlias == "" {
		return "", errors.New("KEYALIAS environment variable not set")
	}

	_, decryptedPrivateKey, err := walletService.GetAndDecryptWalletSecret(ctx, secretID, keyAlias)
	if err != nil {
		return "", fmt.Errorf("failed to get and decrypt admin wallet secret: %w", err)
	}

	return decryptedPrivateKey, nil
}
