package service

import (
	"fmt"
	"strings"
	"time"
	"go.uber.org/zap"

	"auth-service/internal/core/domain/entity"
)

// TokenValidator сервис для валидации токенов
type TokenValidator struct{}

// NewTokenValidator создает новый экземпляр TokenValidator
func NewTokenValidator() *TokenValidator {
	return &TokenValidator{}
}

// ValidateToken проверяет валидность токена
func (v *TokenValidator) ValidateToken(token *entity.Token) error {
	log.Debug("validating token",
		zap.String("token_id", token.ID.String()),
		zap.String("token_type", string(token.Type)),
	)

	if token == nil {
		log.Error("token is nil")
		return fmt.Errorf("token is nil")
	}

	if token.IsRevoked {
		log.Warn("token is revoked",
			zap.String("token_id", token.ID.String()),
		)
		return fmt.Errorf("token is revoked")
	}

	if token.IsExpired() {
		log.Warn("token is expired",
			zap.String("token_id", token.ID.String()),
			zap.Time("expires_at", token.ExpiresAt),
		)
		return fmt.Errorf("token is expired")
	}

	log.Debug("token is valid",
		zap.String("token_id", token.ID.String()),
	)
	return nil
}

// ValidateScopes проверяет наличие необходимых scopes
func (v *TokenValidator) ValidateScopes(token *entity.Token, requiredScopes []string) error {
	log.Debug("validating scopes",
		zap.String("token_id", token.ID.String()),
		zap.Strings("required_scopes", requiredScopes),
		zap.Strings("token_scopes", token.Scopes),
	)

	if len(requiredScopes) == 0 {
		log.Debug("no scopes required")
		return nil
	}

	tokenScopes := make(map[string]bool)
	for _, scope := range token.Scopes {
		tokenScopes[scope] = true
	}

	for _, requiredScope := range requiredScopes {
		if !tokenScopes[requiredScope] {
			log.Warn("missing required scope",
				zap.String("token_id", token.ID.String()),
				zap.String("missing_scope", requiredScope),
			)
			return fmt.Errorf("missing required scope: %s", requiredScope)
		}
	}

	log.Debug("all required scopes present")
	return nil
}

// ValidateAuthCode проверяет валидность кода авторизации
func (v *TokenValidator) ValidateAuthCode(code *entity.AuthCode, clientID string, redirectURI string) error {
	log.Debug("validating authorization code",
		zap.String("code_id", code.ID.String()),
		zap.String("client_id", clientID),
		zap.String("redirect_uri", redirectURI),
	)

	if code == nil {
		log.Error("authorization code is nil")
		return fmt.Errorf("authorization code is nil")
	}

	if code.Used {
		log.Warn("authorization code has been used",
			zap.String("code_id", code.ID.String()),
		)
		return fmt.Errorf("authorization code has already been used")
	}

	if code.IsExpired() {
		log.Warn("authorization code is expired",
			zap.String("code_id", code.ID.String()),
			zap.Time("expires_at", code.ExpiresAt),
		)
		return fmt.Errorf("authorization code is expired")
	}

	if code.ClientID.String() != clientID {
		log.Warn("client ID mismatch",
			zap.String("code_id", code.ID.String()),
			zap.String("expected_client_id", code.ClientID.String()),
			zap.String("provided_client_id", clientID),
		)
		return fmt.Errorf("client ID mismatch")
	}

	if !strings.EqualFold(code.RedirectURI, redirectURI) {
		log.Warn("redirect URI mismatch",
			zap.String("code_id", code.ID.String()),
			zap.String("expected_uri", code.RedirectURI),
			zap.String("provided_uri", redirectURI),
		)
		return fmt.Errorf("redirect URI mismatch")
	}

	log.Debug("authorization code is valid",
		zap.String("code_id", code.ID.String()),
	)
	return nil
}

// ValidateClient проверяет валидность клиента
func (v *TokenValidator) ValidateClient(client *entity.Client, grantType entity.GrantType) error {
	log.Debug("validating client",
		zap.String("client_id", client.ID.String()),
		zap.String("grant_type", string(grantType)),
	)

	if client == nil {
		log.Error("client is nil")
		return fmt.Errorf("client is nil")
	}

	if !client.Active {
		log.Warn("client is inactive",
			zap.String("client_id", client.ID.String()),
		)
		return fmt.Errorf("client is inactive")
	}

	if !client.IsGrantTypeAllowed(grantType) {
		log.Warn("grant type not allowed",
			zap.String("client_id", client.ID.String()),
			zap.String("grant_type", string(grantType)),
			zap.Any("allowed_grant_types", client.GrantTypes),
		)
		return fmt.Errorf("grant type not allowed: %s", grantType)
	}

	log.Debug("client is valid",
		zap.String("client_id", client.ID.String()),
	)
	return nil
}

// ValidateSession проверяет валидность сессии
func (v *TokenValidator) ValidateSession(session *entity.Session) error {
	log.Debug("validating session",
		zap.String("session_id", session.ID.String()),
	)

	if session == nil {
		log.Error("session is nil")
		return fmt.Errorf("session is nil")
	}

	if !session.IsActive() {
		log.Warn("session is not active",
			zap.String("session_id", session.ID.String()),
			zap.String("status", string(session.Status)),
		)
		return fmt.Errorf("session is not active")
	}

	if session.IsExpired() {
		log.Warn("session is expired",
			zap.String("session_id", session.ID.String()),
			zap.Time("expires_at", session.ExpiresAt),
		)
		return fmt.Errorf("session is expired")
	}

	inactiveTime := time.Since(session.LastUsedAt)
	if inactiveTime > 30*time.Minute {
		log.Warn("session inactive timeout",
			zap.String("session_id", session.ID.String()),
			zap.Duration("inactive_time", inactiveTime),
		)
		return fmt.Errorf("session inactive timeout")
	}

	log.Debug("session is valid",
		zap.String("session_id", session.ID.String()),
	)
	return nil
} 