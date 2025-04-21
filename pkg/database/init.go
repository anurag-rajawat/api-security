package database

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	"github.com/anurag-rajawat/api-security/pkg/config"
	"github.com/anurag-rajawat/api-security/pkg/util"
)

type Handler struct {
	Database   *mongo.Database
	Disconnect func() error
}

func (h *Handler) SetupIndices() error {
	return nil
}

func New(ctx context.Context, dbConfig config.DatabaseConfiguration) (*Handler, error) {
	logger := util.GetLogger()

	opts := options.Client().
		ApplyURI(dbConfig.MongoDB.Uri).
		SetAuth(
			options.Credential{
				Username: dbConfig.MongoDB.Username,
				Password: dbConfig.MongoDB.Password,
			},
		)
	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	logger.Infof("connecting to %s database", dbConfig.MongoDB.DatabaseName)
	if err := client.Ping(ctx, readpref.PrimaryPreferred()); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	logger.Infof("connected to %s database", dbConfig.MongoDB.DatabaseName)

	return &Handler{
		Database: client.Database(dbConfig.MongoDB.DatabaseName),
		Disconnect: func() error {
			return client.Disconnect(ctx)
		},
	}, nil
}
