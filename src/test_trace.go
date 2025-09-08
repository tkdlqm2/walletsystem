package main

import (
	"fmt"
	"time"

	"github.com/acecasino/account_manage/pkg/logger"
	"github.com/acecasino/account_manage/pkg/utils"
)

func main() {
	fmt.Println("Testing TraceBlockchain function...")

	// Initialize logger
	logger.InitGlobalLogger()

	// Test the function
	fmt.Println("Calling TraceBlockchain...")
	utils.TraceBlockchain()

	fmt.Println("Waiting 5 seconds...")
	time.Sleep(5 * time.Second)

	fmt.Println("Test completed!")
}
