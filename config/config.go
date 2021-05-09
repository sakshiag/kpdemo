package config

import (
	"log"

	"github.com/kelseyhightower/envconfig"
)

type Configuration struct {
	KMSEndpointURL string
	ROOTKEYCRN     string
	APIKEY         string
	IAMEndpoint    string
}

func ParseEnvConfig(prefix string, conf interface{}) {
	if err := envconfig.Process(prefix, conf); err != nil {
		log.Println("Error parsing kms variables into configuration", err)
	}
}

func GetConfig() Configuration {
	var configuration Configuration
	ParseEnvConfig("kms", &configuration)
	return configuration
}
