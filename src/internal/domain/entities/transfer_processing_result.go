package entities

// TransferProcessingResult represents the result of transfer processing
type TransferProcessingResult struct {
	TotalProcessed int                    `json:"total_processed"`
	Deposits       int                    `json:"deposits"`
	Collects       int                    `json:"collects"`
	Withdraws      int                    `json:"withdraws"`
	Duplicates     int                    `json:"duplicates"`
	Failed         []FailedTransferDetail `json:"failed"`
}

// FailedTransferDetail represents a failed transfer detail
type FailedTransferDetail struct {
	EventID int64  `json:"event_id"`
	Address string `json:"address"`
	Amount  string `json:"amount"`
	Error   string `json:"error"`
}

// TransferBatchData represents batch data for transfer processing
type TransferBatchData struct {
	Accounts   map[string]*ChainAccount `json:"accounts"`
	Currencies map[int]*Currency        `json:"currencies"`
}

// CollectProcessingResult represents the result of collect processing
type CollectProcessingResult struct {
	TotalProcessed int                   `json:"total_processed"`
	Successful     int                   `json:"successful"`
	Failed         []FailedCollectDetail `json:"failed"`
}

// FailedCollectDetail represents a failed collect detail
type FailedCollectDetail struct {
	EventID int64  `json:"event_id"`
	Address string `json:"address"`
	Amount  string `json:"amount"`
	Error   string `json:"error"`
}

// WithdrawProcessingResult represents the result of withdraw processing
type WithdrawProcessingResult struct {
	TotalProcessed int                    `json:"total_processed"`
	Successful     int                    `json:"successful"`
	Failed         []FailedWithdrawDetail `json:"failed"`
}

// FailedWithdrawDetail represents a failed withdraw detail
type FailedWithdrawDetail struct {
	EventID int64  `json:"event_id"`
	Address string `json:"address"`
	Amount  string `json:"amount"`
	Error   string `json:"error"`
}
