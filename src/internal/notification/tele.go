package notification

import (
	"errors"
	"log"
	"math/big"
	"os"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
)

func SendTelMsg(msg string) error {
	// Telegram Bot API Token
	botToken := os.Getenv("TELEGRAM_BOT_TOKEN")      // 봇 토큰을 환경 변수로부터 읽어옴
	group := os.Getenv("TELEGRAM_BOT_MESSAGE_GROUP") // 봇 토큰을 환경 변수로부터 읽어옴
	if botToken == "" || group == "" {
		return errors.New("TELEGRAM_BOT_TOKEN or TELEGRAM_BOT_MESSAGE_GROUP is not set")
	}

	// Telegram 봇 인스턴스 생성
	bot, err := tgbotapi.NewBotAPI(botToken)
	if err != nil {
		return err
	}

	// 봇 정보 출력
	log.Printf("Authorized on account %s", bot.Self.UserName)

	// 메시지 보낼 대상 채팅 ID
	chatID, ok := big.NewInt(0).SetString(group, 10)
	if !ok {
		return errors.New("chatID is not valid")
	}
	// 전송할 메시지 생성
	msgStruct := tgbotapi.NewMessage(chatID.Int64(), msg)

	// 메시지 전송
	_, err = bot.Send(msgStruct)
	if err != nil {
		return err
	}
	return nil
}
