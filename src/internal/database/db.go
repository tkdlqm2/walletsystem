package database

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/acecasino/account_manage/pkg/logger"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

var newDBLock = sync.Mutex{}
var _dbIns *gorm.DB

func NewDB() (*gorm.DB, error) {
	newDBLock.Lock()
	defer newDBLock.Unlock()
	if _dbIns != nil {
		return _dbIns, nil
	}
	// PostgreSQL 연결 문자열
	connStr := fmt.Sprintf("host=%s port=%s user=%s "+
		"password=%s dbname=%s",
		os.Getenv("DB_URL"), os.Getenv("DB_PORT"), os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_DATABASE"))

	newLogger := gormlogger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		gormlogger.Config{
			SlowThreshold: time.Second,  // Slow SQL threshold
			LogLevel:      gormlogger.Error, // Log level
			Colorful:      true,         // Disable color
		},
	)
	fmt.Println("NewDB open new db")
	var err error
	_dbIns, err = gorm.Open(postgres.Open(connStr), &gorm.Config{
		Logger: newLogger,
	})
	if err != nil {
		return nil, err
	}

	return _dbIns, nil
}

func SendErrMsg(db *gorm.DB, code string, err error) {
	sqlStatement := `INSERT INTO error_logs (code, msg) VALUES ($1, $2)`
	msg := fmt.Sprintf("%+v", err)
	fmt.Println(msg)
	tx := db.Exec(sqlStatement, code, msg)
	if tx.Error != nil {
		fmt.Println("SendErrMsg error", tx.Error)
		panic(tx.Error)
	}
}

func Migrate() {
	db, err := NewDB()
	if err != nil {
		fmt.Println("Migrate error", err)
		panic(err)
	}
	db.AutoMigrate(&ErrorLogs{}, &UserWalletBalance{}, &ChainAccount{}, &User{})
}

type ErrorLogs struct {
	gorm.Model
	Code string
	Msg  string
}

type Blockchain struct {
	ID               int    `gorm:"primaryKey;autoIncrement;column:id"`
	Name             string `gorm:"size:50;not null;column:name"`
	RpcURL           string `gorm:"type:text;column:rpc_url"`
	TraceInterval    int    `gorm:"column:trace_interval"`
	WalletType       string `gorm:"size:20;column:wallet_type"`
	LastCheckedBlock int    `gorm:"column:last_checked_block"`
	ActiveWatch      bool   `gorm:"default:false;not null;column:active_watch"`
	FinalityBlock    int    `gorm:"default:0;column:finality_block"`
	ScanURL          string `gorm:"column:scan_url"`
	ChainID          int    `gorm:"column:chain_id"`
}

func (Blockchain) TableName() string {
	return "blockchain"
}

type Currency struct {
	ID           int        `gorm:"primaryKey;autoIncrement;column:id"`
	ChainID      int        `gorm:"column:chain_id"`
	Blockchain   Blockchain `gorm:"foreignKey:ChainID;references:ID"`
	Name         string     `gorm:"size:50;not null;column:name"`
	Symbol       string     `gorm:"size:20;not null;uniqueIndex:currency_symbol_idx;column:symbol"`
	Address      string     `gorm:"size:200;not null;column:address"`
	Price        float64    `gorm:"type:numeric(38,18);column:price"`
	Decimal      int        `gorm:"type:numeric;column:decimal"`
	ActiveWatch  bool       `gorm:"default:false;not null;column:active_watch"`
	DefaultValue bool       `gorm:"column:default_value"`
}

type WithdrawInfo struct {
	ID         int       `gorm:"column:id"`
	UserID     int       `gorm:"column:user_id"`
	CurrencyID int       `gorm:"column:currency_id"`
	ToAddress  string    `gorm:"column:to_address"`
	Amount     string    `gorm:"column:amount"`
	CreateAt   time.Time `gorm:"column:create_at"`
	Process    string    `gorm:"column:process"`
	TxRef      int       `gorm:"column:tx_ref"`
	Fee        float64   `gorm:"column:fee"`
	Take       float64   `gorm:"column:take"`
	TxHash     string    `gorm:"column:tx_hash"`
}
type User struct {
	ID         int       `gorm:"primaryKey;autoIncrement;column:id"`
	Username   string    `gorm:"size:50;not null;column:username"`
	Email      string    `gorm:"size:255;not null;uniqueIndex:users_email_idx;column:email"`
	Lang       string    `gorm:"size:4;column:lang"`
	BirthDay   time.Time `gorm:"column:birth_day;default:1900-01-01"`
	Marketing  bool      `gorm:"column:marketing;default:true"`
	CreateAt   time.Time `gorm:"column:create_at;default:CURRENT_TIMESTAMP;not null"`
	Addrbook   string    `gorm:"column:addrbook"`
	RedeemCode string    `gorm:"size:100;column:redeem_code"`
	RedeemIP   int64     `gorm:"type:numeric(10);uniqueIndex:users_redeem_ip_idx;column:redeem_ip"`
	Block      bool      `gorm:"column:block"`
}

func (User) TableName() string {
	return "users"
}

type ChainAccount struct {
	ID             int    `gorm:"primaryKey;autoIncrement;column:id"`
	UserID         int    `gorm:"column:user_id"`
	WalletType     string `gorm:"column:wallet_type"`
	AccountAddress string `gorm:"column:account_address"`
	PrivateKey     string `gorm:"column:private_key"`
}

func (ChainAccount) TableName() string {
	return "chain_accounts"
}

func (Currency) WithdrawInfo() string {
	return "withdraw_history"
}

func (Currency) TableName() string {
	return "currency"
}

type UserWalletBalance struct {
	ID             int        `gorm:"primaryKey;autoIncrement;column:id"`
	ChainID        int        `gorm:"column:chain_id"`
	Blockchain     Blockchain `gorm:"foreignKey:ChainID;references:ID"`
	ChainAccountID int        `gorm:"column:chain_account_id"`
	Balance        string     `gorm:"type:numeric(38,18);column:balance"`
}

func (UserWalletBalance) TableName() string {
	return "user_wallet_balance"
}

// 이메일로 사용자의 private key들을 조회하는 함수
func GetPrivateKeyUsingEmail(db *gorm.DB, email string) (map[string]string, error) {
	log := logger.GetLogger().WithField("email_hash", HashEmail(email))

	if email == "" {
		return nil, errors.New("email cannot be empty")
	}

	// 이메일로 user_id를 먼저 조회
	userID, err := GetUserIDByEmail(db, email)
	log.WithField("user_id", userID)
	if err != nil {
		log.WithError(err).Error("Failed to get user ID by email")
		return nil, err
	}

	if userID == 0 {
		return nil, errors.New("user not found")
	}

	// user_id로 모든 지갑의 private key 조회
	privateKeys, err := GetPrivateKeysByUserID(db, userID)
	log.WithField("wallet_count", len(privateKeys))
	if err != nil {
		log.WithError(err).Error("Failed to get private keys by user ID")
		return nil, err
	}

	if len(privateKeys) == 0 {
		return nil, errors.New("no wallet found for user")
	}

	log.Info("Private keys retrieved successfully")
	return privateKeys, nil
}

// 특정 지갑 타입의 private key만 조회하는 함수
func GetPrivateKeyUsingEmailAndWalletType(db *gorm.DB, email, walletType string) (string, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"email_hash":  HashEmail(email),
		"wallet_type": walletType,
	})

	if email == "" || walletType == "" {
		return "", errors.New("email and wallet_type cannot be empty")
	}

	// 먼저 이메일로 사용자 ID 조회
	userID, err := GetUserIDByEmail(db, email)
	if err != nil {
		log.WithError(err).Error("Failed to get user ID by email")
		return "", err
	}
	
	if userID == 0 {
		log.Warn("User not found")
		return "", errors.New("user not found")
	}

	// GORM 방식으로 chain account 조회
	var chainAccount ChainAccount
	err = db.Where("user_id = ? AND wallet_type = ?", userID, walletType).First(&chainAccount).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			log.Warn("No wallet found for user and wallet type")
			return "", errors.New("wallet not found")
		}
		log.WithError(err).Error("Database query failed")
		return "", err
	}

	if chainAccount.PrivateKey == "" || chainAccount.PrivateKey == "test" {
		log.Warn("Private key is empty or test value")
		return "", errors.New("invalid private key found")
	}

	log.Info("Private key retrieved successfully")
	return chainAccount.PrivateKey, nil
}

// 사용자 ID로 모든 지갑의 private key 조회 (헬퍼 함수)
func GetPrivateKeysByUserID(db *gorm.DB, userID int) (map[string]string, error) {
	var chainAccounts []ChainAccount

	// GORM의 Select 메서드를 사용하여 필요한 wallet_type과 private_key 컬럼만 조회합니다.
	err := db.Select("wallet_type, private_key").Where("user_id = ?", userID).Find(&chainAccounts).Error
	if err != nil {
		return nil, fmt.Errorf("failed to query private keys: %w", err)
	}

	privateKeys := make(map[string]string)
	for _, account := range chainAccounts {
		// 소문자로 변환하여 일관성 유지
		walletKey := strings.ToLower(account.WalletType)
		privateKeys[walletKey] = account.PrivateKey
	}
	fmt.Println("getPrivateKeysByUserID", privateKeys)

	return privateKeys, nil
}

// 이메일로 사용자 ID 조회 (이미 있을 수 있지만 재정의)
func GetUserIDByEmail(db *gorm.DB, email string) (int, error) {
	// GORM 방식으로 변경
	var user User
	err := db.Where("email = ?", email).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return 0, nil // 사용자 없음
		}
		return 0, fmt.Errorf("failed to query user ID: %w", err)
	}

	return user.ID, nil
}

// 보안을 위한 이메일 해싱 함수 (로깅용)
func HashEmail(email string) string {
	if email == "" {
		return "empty"
	}

	hash := sha256.Sum256([]byte(email))
	return hex.EncodeToString(hash[:8]) // 처음 8바이트만 사용
}

// 트랜잭션에서 사용할 수 있는 안전한 버전
func GetPrivateKeyForTransaction(db *gorm.DB, email, walletType string) (string, error) {
	log := logger.GetLogger().WithFields(map[string]interface{}{
		"email_hash":  HashEmail(email),
		"wallet_type": walletType,
		"operation":   "transaction_key_retrieval",
	})

	// 입력 검증
	if email == "" || walletType == "" {
		return "", errors.New("email and wallet_type are required")
	}

	// 지원되는 지갑 타입 검증
	supportedWallets := map[string]bool{
		"ETHEREUM": true,
		"TRON":     true,
	}

	if !supportedWallets[strings.ToUpper(walletType)] {
		return "", errors.New("unsupported wallet type")
	}

	// private key 조회
	privateKey, err := GetPrivateKeyUsingEmailAndWalletType(db, email, strings.ToUpper(walletType))
	if err != nil {
		log.WithError(err).Error("Failed to retrieve private key for transaction")
		return "", err
	}

	// 추가 검증 (private key 형식 검증 등)
	if len(privateKey) < 32 {
		log.Error("Retrieved private key is too short")
		return "", errors.New("invalid private key format")
	}

	log.Info("Private key retrieved successfully for transaction")
	return privateKey, nil
}

// GetCurrency는 토큰 심볼로 통화 정보를 가져옵니다
func GetCurrency(db *gorm.DB, token string) (*Currency, error) {
	var currency Currency
	result := db.Where("symbol = ?", token).First(&currency)
	if result.Error != nil {
		return nil, result.Error
	}
	return &currency, nil
}
