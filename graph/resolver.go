package graph

import (
	"go.uber.org/zap"

	"github.com/anurag-rajawat/api-security/graph/generated"
	"github.com/anurag-rajawat/api-security/pkg/database"
	"github.com/anurag-rajawat/api-security/pkg/util"
)

//go:generate go run github.com/99designs/gqlgen generate

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

type Resolver struct {
	mongoHandler *database.Handler
	Logger       *zap.SugaredLogger
}

func NewConfig(mongoHandler *database.Handler) generated.Config {
	return generated.Config{
		Resolvers: &Resolver{
			mongoHandler: mongoHandler,
			Logger:       util.GetLogger(),
		},
	}
}
