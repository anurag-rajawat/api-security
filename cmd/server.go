package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/anurag-rajawat/api-security/pkg/config"
	"github.com/anurag-rajawat/api-security/pkg/database"
	"github.com/anurag-rajawat/api-security/pkg/handler"
	"github.com/anurag-rajawat/api-security/pkg/middleware"
	"github.com/anurag-rajawat/api-security/pkg/util"
)

func main() {
	ctx := util.SetupSignalHandler()
	// Todo: Add a flag for configFilePath and logLevel
	util.InitLogger("debug")
	logger := util.GetLogger()

	configuration, err := config.New("", logger)
	if err != nil {
		logger.Fatal(err)
	}

	mongoHandler, err := database.New(ctx, configuration.Database)
	if err != nil {
		logger.Fatal(err)
	}
	defer func() {
		if err := mongoHandler.Disconnect(); err != nil {
			logger.Fatal(err)
		}
	}()

	//if err := mongoHandler.SetupIndices(); err != nil {
	//	logger.Fatal(err)
	//}

	if logger.Level() == zap.DebugLevel {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(middleware.StructuredLogger(logger))
	router.Use(handler.GinContextToContextMiddleware())

	v1 := router.Group("/api/v1")
	v1.POST("catalog", handler.Catalog(mongoHandler))

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%v", configuration.Server.Port),
		Handler: router,
	}
	go func() {
		logger.Infof("Listening and serving on :%d", configuration.Server.Port)
		if err = srv.ListenAndServe(); err != nil && !errors.Is(http.ErrServerClosed, err) {
			logger.Fatalf("Failed to start server due to %s", err)
		}
	}()

	<-ctx.Done()
	logger.Info("Shutdown signal received, shutting down...")

	if err := srv.Shutdown(context.Background()); err != nil {
		logger.Fatalf("Server forced to shutdown: %s", err)
	}

	logger.Info("All workers finished. Stopped server.")
}
