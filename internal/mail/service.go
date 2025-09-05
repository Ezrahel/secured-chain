package mail

import (
	"auth-service/internal/config"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/smtp"
	"time"

	"gopkg.in/gomail.v2"
)

type Service struct {
	config config.SMTPConfig
	dialer *gomail.Dialer
}

type EmailData struct {
	Name        string
	Email       string
	Token       string
	ConfirmURL  string
	ResetURL    string
	ExpiryHours int
}

type customDialer struct {
	*gomail.Dialer
	timeout time.Duration
}

type Dialer interface {
	Dial() (gomail.SendCloser, error)
	DialAndSend(messages ...*gomail.Message) error
}

func NewCustomDialer(host string, port int, username, password string, timeout time.Duration) *customDialer {
	return &customDialer{
		Dialer:  gomail.NewDialer(host, port, username, password),
		timeout: timeout,
	}
}
func (d *customDialer) Dial() (gomail.SendCloser, error) {
	netDialer := &net.Dialer{
		Timeout: d.timeout,
	}

	addr := fmt.Sprintf("%s:%d", d.Dialer.Host, d.Dialer.Port)
	conn, err := netDialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}

	if d.Dialer.Port == 465 { // SMTPS
		tlsConn := tls.Client(conn, d.Dialer.TLSConfig)
		if err := tlsConn.HandshakeContext(context.Background()); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		conn = tlsConn
	}

	client, err := smtp.NewClient(conn, d.Dialer.Host)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create SMTP client: %w", err)
	}

	if d.Dialer.Username != "" {
		auth := smtp.PlainAuth("", d.Dialer.Username, d.Dialer.Password, d.Dialer.Host)
		if err := client.Auth(auth); err != nil {
			client.Close()
			return nil, fmt.Errorf("failed to authenticate: %w", err)
		}
	}

	return &smtpSendCloser{client}, nil
}

// Add this helper type to implement gomail.SendCloser
type smtpSendCloser struct {
	*smtp.Client
}

func (d *customDialer) DialAndSend(m ...*gomail.Message) error {
	s, err := d.Dial()
	if err != nil {
		return err
	}
	defer s.Close()

	for _, msg := range m {
		if err := gomail.Send(s, msg); err != nil {
			return err
		}
	}
	return nil
}
func (s *smtpSendCloser) Send(from string, to []string, msg io.WriterTo) error {
	if err := s.Mail(from); err != nil {
		return fmt.Errorf("failed to set FROM address: %w", err)
	}

	for _, addr := range to {
		if err := s.Rcpt(addr); err != nil {
			return fmt.Errorf("failed to add recipient %s: %w", addr, err)
		}
	}

	w, err := s.Data()
	if err != nil {
		return fmt.Errorf("failed to create message writer: %w", err)
	}
	defer w.Close()

	if _, err := msg.WriteTo(w); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	return nil
}

func (s *smtpSendCloser) Close() error {
	return s.Client.Close()
}

// Update the Service struct to use an interface instead of concrete type

func NewService(config config.SMTPConfig) *Service {
	baseDialer := gomail.NewDialer(config.Host, config.Port, config.User, config.Password)

	dialer := &customDialer{
		Dialer:  baseDialer,
		timeout: config.Timeout,
	}

	dialer.TLSConfig = &tls.Config{
		ServerName: config.Host,
		MinVersion: tls.VersionTLS12,
	}

	return &Service{
		config: config,
		dialer: dialer.Dialer, // Now this works because customDialer implements Dialer interface
	}
}
func (s *Service) SendConfirmationEmail(to, name, token, confirmURL string) error {
	data := EmailData{
		Name:        name,
		Email:       to,
		Token:       token,
		ConfirmURL:  fmt.Sprintf("%s?token=%s", confirmURL, token),
		ExpiryHours: 24,
	}

	subject := "Confirm your email address"
	htmlBody, err := s.renderTemplate("confirmation", data)
	if err != nil {
		return fmt.Errorf("failed to render confirmation email template: %w", err)
	}

	textBody := fmt.Sprintf(`
Hi %s,

Please confirm your email address by clicking the link below:
%s

This link will expire in %d hours.

If you didn't create an account, please ignore this email.

Best regards,
The Auth Service Team
`, data.Name, data.ConfirmURL, data.ExpiryHours)

	return s.sendEmail(to, subject, htmlBody, textBody)
}

func (s *Service) SendPasswordResetEmail(to, name, token, resetURL string) error {
	data := EmailData{
		Name:        name,
		Email:       to,
		Token:       token,
		ResetURL:    fmt.Sprintf("%s?token=%s", resetURL, token),
		ExpiryHours: 1,
	}

	subject := "Reset your password"
	htmlBody, err := s.renderTemplate("password_reset", data)
	if err != nil {
		return fmt.Errorf("failed to render password reset email template: %w", err)
	}

	textBody := fmt.Sprintf(`
Hi %s,

You requested to reset your password. Click the link below to set a new password:
%s

This link will expire in %d hour.

If you didn't request a password reset, please ignore this email.

Best regards,
The Auth Service Team
`, data.Name, data.ResetURL, data.ExpiryHours)

	return s.sendEmail(to, subject, htmlBody, textBody)
}

func (s *Service) sendEmail(to, subject, htmlBody, textBody string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", s.config.From)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", textBody)
	m.AddAlternative("text/html", htmlBody)

	// Add security headers
	m.SetHeader("X-Priority", "1")
	m.SetHeader("X-MSMail-Priority", "High")
	m.SetHeader("Importance", "High")

	if err := s.dialer.DialAndSend(m); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

func (s *Service) renderTemplate(templateName string, data EmailData) (string, error) {
	var tmpl *template.Template
	var err error

	switch templateName {
	case "confirmation":
		tmpl, err = template.New("confirmation").Parse(confirmationEmailTemplate)
	case "password_reset":
		tmpl, err = template.New("password_reset").Parse(passwordResetEmailTemplate)
	default:
		return "", fmt.Errorf("unknown template: %s", templateName)
	}

	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

const confirmationEmailTemplate = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Confirm Your Email</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #007bff; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background: #f8f9fa; }
        .button { display: inline-block; padding: 12px 24px; background: #28a745; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
        .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to Auth Service!</h1>
        </div>
        <div class="content">
            <h2>Hi {{.Name}},</h2>
            <p>Thank you for creating an account with us. Please confirm your email address to complete your registration.</p>
            <p>
                <a href="{{.ConfirmURL}}" class="button">Confirm Email Address</a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all; background: #e9ecef; padding: 10px; border-radius: 4px;">{{.ConfirmURL}}</p>
            <p><strong>This link will expire in {{.ExpiryHours}} hours.</strong></p>
            <p>If you didn't create an account, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>Best regards,<br>The Auth Service Team</p>
        </div>
    </div>
</body>
</html>
`

const passwordResetEmailTemplate = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Your Password</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #dc3545; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background: #f8f9fa; }
        .button { display: inline-block; padding: 12px 24px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
        .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Reset Request</h1>
        </div>
        <div class="content">
            <h2>Hi {{.Name}},</h2>
            <p>You requested to reset your password. Click the button below to set a new password:</p>
            <p>
                <a href="{{.ResetURL}}" class="button">Reset Password</a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all; background: #e9ecef; padding: 10px; border-radius: 4px;">{{.ResetURL}}</p>
            <p><strong>This link will expire in {{.ExpiryHours}} hour.</strong></p>
            <p>If you didn't request a password reset, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>Best regards,<br>The Auth Service Team</p>
        </div>
    </div>
</body>
</html>
`
