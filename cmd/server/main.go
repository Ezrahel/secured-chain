package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auth-service/internal/api"
	"auth-service/internal/auth"
	"auth-service/internal/config"
	"auth-service/internal/crypto"
	"auth-service/internal/db"
	"auth-service/internal/mail"
	"auth-service/internal/middleware"
	"auth-service/internal/services"

	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"
	"github.com/rs/cors"
	_ "github.com/lib/pq"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load configuration:", err)
	}

	// Initialize database
	database, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer database.Close()

	// Test database connection
	if err := database.Ping(); err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	// Initialize Redis
	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisURL,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	defer redisClient.Close()

	// Test Redis connection
	ctx := context.Background()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Fatal("Failed to connect to Redis:", err)
	}

	// Initialize database queries
	queries := db.New(database)

	// Initialize services
	cryptoService := crypto.NewService(cfg.EncryptionKey)
	mailService := mail.NewService(cfg.SMTP)
	authService := auth.NewService(cfg.JWT, cryptoService)
	userService := services.NewUserService(queries, cryptoService, mailService, authService, cfg)
	auditService := services.NewAuditService(queries, cryptoService)

	// Initialize API handlers
	handlers := api.NewHandlers(userService, authService, auditService, cfg)

	// Initialize middleware
	middlewareManager := middleware.NewManager(redisClient, cfg)

	// Setup router
	router := mux.NewRouter()
	
	// Apply global middleware
	router.Use(middlewareManager.RequestLogger)
	router.Use(middlewareManager.Recovery)
	router.Use(middlewareManager.SecurityHeaders)
	router.Use(middlewareManager.RateLimit)

	// Setup CORS
	c := cors.New(cors.Options{
		AllowedOrigins:   cfg.CORS.AllowedOrigins,
		AllowedMethods:   cfg.CORS.AllowedMethods,
		AllowedHeaders:   cfg.CORS.AllowedHeaders,
		AllowCredentials: true,
	})
	
	// API routes
	api := router.PathPrefix("/api/v1").Subrouter()
	
	// Public routes
	api.HandleFunc("/signup", handlers.Signup).Methods("POST")
	api.HandleFunc("/login", handlers.Login).Methods("POST")
	api.HandleFunc("/confirm-email", handlers.ConfirmEmail).Methods("GET")
	api.HandleFunc("/password-reset/request", handlers.RequestPasswordReset).Methods("POST")
	api.HandleFunc("/password-reset/confirm", handlers.ConfirmPasswordReset).Methods("POST")
	api.HandleFunc("/token/refresh", handlers.RefreshToken).Methods("POST")

	// Protected routes
	protected := api.PathPrefix("").Subrouter()
	protected.Use(middlewareManager.Authenticate)
	
	protected.HandleFunc("/logout", handlers.Logout).Methods("POST")
	protected.HandleFunc("/sessions", handlers.GetSessions).Methods("GET")
	protected.HandleFunc("/sessions/revoke", handlers.RevokeSession).Methods("POST")
	protected.HandleFunc("/mfa/enable", handlers.EnableMFA).Methods("POST")
	protected.HandleFunc("/mfa/verify", handlers.VerifyMFA).Methods("POST")
	protected.HandleFunc("/mfa/disable", handlers.DisableMFA).Methods("POST")

	// Health check
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}).Methods("GET")

	// Metrics endpoint
	if cfg.MetricsEnabled {
		router.HandleFunc(cfg.MetricsPath, handlers.Metrics).Methods("GET")
	}

	// Create server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", cfg.Host, cfg.Port),
		Handler:      c.Handler(router),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("Server starting on %s:%s", cfg.Host, cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Server failed to start:", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Server shutting down...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exited")
}