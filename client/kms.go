package client

import (
	"context"

	kp "github.com/IBM/keyprotect-go-client"
	"github.com/kp-lab/kpdemo/config"
	"go.uber.org/zap"
)

//NewKeyProtectClient - Create Key Protect Client
func NewKeyProtectClient(ctx context.Context, logger *zap.Logger, cnfg *config.Configuration, instanceID string) (*kp.Client, error) {

	logger.Info("NewKeyProtectClient Invoked")

	options := kp.ClientConfig{
		BaseURL:    cnfg.KMSEndpointURL,
		APIKey:     cnfg.APIKEY,
		InstanceID: instanceID,
		TokenURL:   cnfg.IAMEndpoint + "/oidc/token",
		Verbose:    2,
	}

	kpClient, err := kp.New(options, kp.DefaultTransport())
	if err != nil {
		logger.Error("Error connecting to key protect", zap.Error(err))
		return nil, err
	}

	return kpClient, nil

}
