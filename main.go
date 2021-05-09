package main

import (
	"context"
	"os"
	"time"

	"github.com/kp-lab/kpdemo/config"
	"github.com/kp-lab/kpdemo/decrypt"
	"github.com/kp-lab/kpdemo/encrypt"
	"go.uber.org/zap"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cfg := config.GetConfig()
	logger, _ := zap.NewProduction()
	data := []byte(os.Args[1])
	enData, err := encrypt.EncryptObject(ctx, data, logger, cfg)
	if err != nil {
		logger.Error("Error:", zap.Error(err))
	}
	logger.Info("Encrypted Data:", zap.Any("Data:", enData))

	undata, err := decrypt.DecryptObject(ctx, enData, *logger, cfg)
	if err != nil {
		logger.Error("Error:", zap.Error(err))
	}
	logger.Info("UNEncrypted Data:", zap.Any("Data:", undata))
}
