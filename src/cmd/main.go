package main

import (
	"fmt"

	"github.com/acecasino/account_manage/internal/database"
	"github.com/acecasino/account_manage/internal/handler"
	"github.com/acecasino/account_manage/internal/notification"
	"github.com/acecasino/account_manage/pkg/logger"
	"github.com/acecasino/account_manage/pkg/utils"
	"github.com/joho/godotenv"
	"github.com/robfig/cron/v3"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
		panic(err)
	}
	// am.Migrate()
}

func main() {

	logger.InitGlobalLogger()
	notification.SendTelMsg("Account Manage Server Start")
	db, err := database.NewDB()
	if err != nil {
		fmt.Println("main NewDB error", err)
		panic(err)
	}

	utils.InitData(db)

	c := cron.New(cron.WithSeconds())
	_, err = c.AddFunc("*/10 * * * * *", utils.TraceBlockchain)
	if err != nil {
		fmt.Println("AddFunc TraceBlockchain", err)
		panic(err)
	}
	_, err = c.AddFunc("*/10 * * * * *", utils.CheckLastWithdraw)
	if err != nil {
		fmt.Println("AddFunc CheckLastWithdraw", err)
		panic(err)
	}
	c.Start()

	// 환경 변수 사용
	go handler.RestAPI()
	select {}
}
