package services

import (
	"auth-service/internal/crypto"
	"auth-service/internal/db"
	"auth-service/internal/models"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type AuditService struct {
	queries       *db.Queries
	cryptoService *crypto.Service
}

func NewAuditService(queries *db.Queries, cryptoService *crypto.Service) *AuditService {
	return &AuditService{
		queries:       queries,
		cryptoService: cryptoService,
	}
}

func (s *AuditService) LogEvent(ctx context.Context, event *models.AuditEvent) error {
	// Get the last hash for chain integrity
	var prevHash []byte
	if lastLog, err := s.queries.GetLastAuditLogHash(ctx); err == nil {
		prevHash = lastLog
	}

	// Serialize event payload
	payloadBytes, err := json.Marshal(event.Payload)
	if err != nil {
		return fmt.Errorf("failed to marshal event payload: %w", err)
	}

	// Generate hash chain
	eventData := fmt.Sprintf("%s|%s|%s|%s|%v",
		event.UserID,
		event.EventType,
		string(payloadBytes),
		event.IPAddress,
		event.Timestamp.Unix(),
	)

	hash := s.cryptoService.GenerateHashChain(prevHash, []byte(eventData))

	// Parse user ID
	var userID pgtype.UUID
	if event.UserID != "" {
		if id, err := uuid.Parse(event.UserID); err == nil {
			userID = pgtype.UUID{
				Bytes: id,
				Valid: true,
			}
		}
	}

	// Parse IP address
	var ipAddr netip.Addr
	var ipAddrPtr *netip.Addr
	if event.IPAddress != "" {
		parsedIP := net.ParseIP(event.IPAddress)
		if addr, err := ipToNetipAddr(parsedIP); err == nil {
			ipAddr = addr
			ipAddrPtr = &ipAddr
		}
	}

	// Store audit log
	_, err = s.queries.CreateAuditLog(ctx, db.CreateAuditLogParams{
		UserID:       userID,
		EventType:    event.EventType,
		EventPayload: payloadBytes,
		IpAddress:    ipAddrPtr,
		UserAgent: pgtype.Text{
			String: event.UserAgent,
			Valid:  event.UserAgent != "",
		},
		PrevHash: prevHash,
		Hash:     hash,
	})

	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	return nil
}

func (s *AuditService) LogSignup(ctx context.Context, userID, email string, r *http.Request) {
	event := &models.AuditEvent{
		UserID:    userID,
		EventType: "user_signup",
		Payload: map[string]interface{}{
			"email": email,
		},
		IPAddress: s.getClientIP(r).String(),
		UserAgent: r.UserAgent(),
		Timestamp: time.Now(),
	}
	s.LogEvent(ctx, event)
}

func (s *AuditService) LogLogin(ctx context.Context, userID, email string, success bool, r *http.Request) {
	eventType := "user_login_success"
	if !success {
		eventType = "user_login_failed"
	}

	event := &models.AuditEvent{
		UserID:    userID,
		EventType: eventType,
		Payload: map[string]interface{}{
			"email":   email,
			"success": success,
		},
		IPAddress: s.getClientIP(r).String(),
		UserAgent: r.UserAgent(),
		Timestamp: time.Now(),
	}
	s.LogEvent(ctx, event)
}

func (s *AuditService) LogEmailConfirmation(ctx context.Context, userID, email string, r *http.Request) {
	event := &models.AuditEvent{
		UserID:    userID,
		EventType: "email_confirmed",
		Payload: map[string]interface{}{
			"email": email,
		},
		IPAddress: s.getClientIP(r).String(),
		UserAgent: r.UserAgent(),
		Timestamp: time.Now(),
	}
	s.LogEvent(ctx, event)
}

func (s *AuditService) LogPasswordReset(ctx context.Context, userID, email string, r *http.Request) {
	event := &models.AuditEvent{
		UserID:    userID,
		EventType: "password_reset",
		Payload: map[string]interface{}{
			"email": email,
		},
		IPAddress: s.getClientIP(r).String(),
		UserAgent: r.UserAgent(),
		Timestamp: time.Now(),
	}
	s.LogEvent(ctx, event)
}

func (s *AuditService) LogTokenRefresh(ctx context.Context, userID string, r *http.Request) {
	event := &models.AuditEvent{
		UserID:    userID,
		EventType: "token_refresh",
		Payload: map[string]interface{}{
			"action": "refresh_token",
		},
		IPAddress: s.getClientIP(r).String(),
		UserAgent: r.UserAgent(),
		Timestamp: time.Now(),
	}
	s.LogEvent(ctx, event)
}

func (s *AuditService) LogLogout(ctx context.Context, userID string, r *http.Request) {
	event := &models.AuditEvent{
		UserID:    userID,
		EventType: "user_logout",
		Payload: map[string]interface{}{
			"action": "logout",
		},
		IPAddress: s.getClientIP(r).String(),
		UserAgent: r.UserAgent(),
		Timestamp: time.Now(),
	}
	s.LogEvent(ctx, event)
}

func (s *AuditService) LogMFAEvent(ctx context.Context, userID, action string, success bool, r *http.Request) {
	event := &models.AuditEvent{
		UserID:    userID,
		EventType: "mfa_event",
		Payload: map[string]interface{}{
			"action":  action,
			"success": success,
		},
		IPAddress: s.getClientIP(r).String(),
		UserAgent: r.UserAgent(),
		Timestamp: time.Now(),
	}
	s.LogEvent(ctx, event)
}

func (s *AuditService) LogSuspiciousActivity(ctx context.Context, userID, reason string, r *http.Request) {
	event := &models.AuditEvent{
		UserID:    userID,
		EventType: "suspicious_activity",
		Payload: map[string]interface{}{
			"reason": reason,
		},
		IPAddress: s.getClientIP(r).String(),
		UserAgent: r.UserAgent(),
		Timestamp: time.Now(),
	}
	s.LogEvent(ctx, event)
}

func (s *AuditService) getClientIP(r *http.Request) net.IP {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if parsedIP := net.ParseIP(ip); parsedIP != nil {
				return parsedIP
			}
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if parsedIP := net.ParseIP(xri); parsedIP != nil {
			return parsedIP
		}
	}

	// Use remote address
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}
