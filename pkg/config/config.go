package config

import (
	"github.com/goccy/go-json"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

const (
	defaultConfigFilePath = "conf/default.yaml"
	defaultServerPort     = 9999
)

type ServerConfiguration struct {
	Port           int    `json:"port"`
	LogLevel       string `json:"logLevel,omitempty"`
	EnableProfiler bool   `json:"enableProfiler"`
}

type MongoDBConfiguration struct {
	Credential     string `json:"credential"`
	Uri            string `json:"uri"`
	DatabaseName   string `json:"databaseName"`
	CollectionName string `json:"collectionName"`
	Username       string `json:"username"`
	Password       string `json:"password"`
}

type DatabaseConfiguration struct {
	MongoDB MongoDBConfiguration `json:"mongoDB"`
}

type Configuration struct {
	Server   ServerConfiguration   `json:"server"`
	Database DatabaseConfiguration `json:"database"`
}

func New(configFilePath string, logger *zap.SugaredLogger) (Configuration, error) {
	if configFilePath == "" {
		configFilePath = defaultConfigFilePath
		logger.Warnf("config file path is empty, using default: %s", defaultConfigFilePath)
	}

	viper.SetConfigFile(configFilePath)
	viper.SetConfigType("yaml")
	if err := viper.ReadInConfig(); err != nil {
		return Configuration{}, err
	}

	var configuration Configuration
	if err := viper.Unmarshal(&configuration); err != nil {
		return Configuration{}, err
	}

	if configuration.Server.Port == 0 {
		configuration.Server.Port = defaultServerPort
		logger.Warnf("no server port set, using default: %d", configuration.Server.Port)
	}

	dbUserName, dbPassword := configuration.Database.MongoDB.Username, configuration.Database.MongoDB.Password
	configuration.Database.MongoDB.Username = ""
	configuration.Database.MongoDB.Password = ""

	if logger.Level() == zap.DebugLevel {
		bytes, err := json.Marshal(configuration)
		if err != nil {
			return Configuration{}, err
		}
		logger.Debug(string(bytes))
	}

	configuration.Database.MongoDB.Username = dbUserName
	configuration.Database.MongoDB.Password = dbPassword

	return configuration, nil
}
