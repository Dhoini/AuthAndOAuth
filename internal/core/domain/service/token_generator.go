package service

import (
	"AuthAndOauth/internal/core/domain/entity"
	"crypto/rand"
	"encoding/base64"
	"go.uber.org/zap"
	"time"

	"github.com/google/uuid"
)

// TokenConfig конфигурация для генерации токенов
type TokenConfig struct {
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	TokenLength          int
}

// DefaultTokenConfig возвращает конфигурацию по умолчанию
func DefaultTokenConfig() *TokenConfig {
	return &TokenConfig{
		AccessTokenDuration:  time.Hour,
		RefreshTokenDuration: time.Hour * 24 * 7, // 7 дней
		TokenLength:          32,
	}
}

// TokenGenerator сервис для генерации токенов
type TokenGenerator struct {
	config *TokenConfig
}

// NewTokenGenerator создает новый экземпляр TokenGenerator
func NewTokenGenerator(config *TokenConfig) *TokenGenerator {
	if config == nil {
		config = DefaultTokenConfig()
	}
	return &TokenGenerator{config: config}
}

// GenerateTokenPair генерирует пару access и refresh токенов
func (g *TokenGenerator) GenerateTokenPair(userID, clientID uuid.UUID, scopes []string) (*entity.Token, *entity.Token, error) {
	log.Debug("generating token pair",
		zap.String("user_id", userID.String()),
		zap.String("client_id", clientID.String()),
		zap.Strings("scopes", scopes),
	)

	accessToken, err := g.generateToken(userID, clientID, entity.AccessToken, scopes, g.config.AccessTokenDuration)
	if err != nil {
		log.Error("failed to generate access token",
			zap.String("user_id", userID.String()),
			zap.String("client_id", clientID.String()),
			zap.Error(err),
		)
		return nil, nil, err
	}

	refreshToken, err := g.generateToken(userID, clientID, entity.RefreshToken, scopes, g.config.RefreshTokenDuration)
	if err != nil {
		log.Error("failed to generate refresh token",
			zap.String("user_id", userID.String()),
			zap.String("client_id", clientID.String()),
			zap.Error(err),
		)
		return nil, nil, err
	}

	log.Debug("token pair generated successfully",
		zap.String("access_token_id", accessToken.ID.String()),
		zap.String("refresh_token_id", refreshToken.ID.String()),
	)

	return accessToken, refreshToken, nil
}

// GenerateAuthCode генерирует код авторизации
func (g *TokenGenerator) GenerateAuthCode(userID, clientID uuid.UUID, redirectURI string, scopes []string, codeChallenge, codeMethod string) (*entity.AuthCode, error) {
	log.Debug("generating authorization code",
		zap.String("user_id", userID.String()),
		zap.String("client_id", clientID.String()),
		zap.String("redirect_uri", redirectURI),
		zap.Strings("scopes", scopes),
		zap.String("code_method", codeMethod),
	)

	code, err := g.generateRandomString(g.config.TokenLength)
	if err != nil {
		log.Error("failed to generate random string for auth code",
			zap.String("user_id", userID.String()),
			zap.String("client_id", clientID.String()),
			zap.Error(err),
		)
		return nil, err
	}

	now := time.Now()
	authCode := &entity.AuthCode{
		ID:            uuid.New(),
		Code:          code,
		UserID:        userID,
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		Scopes:        scopes,
		CodeChallenge: codeChallenge,
		CodeMethod:    codeMethod,
		ExpiresAt:     now.Add(10 * time.Minute), // Код авторизации действителен 10 минут
		CreatedAt:     now,
		Used:          false,
	}

	log.Debug("authorization code generated successfully",
		zap.String("code_id", authCode.ID.String()),
		zap.Time("expires_at", authCode.ExpiresAt),
	)

	return authCode, nil
}

// generateToken генерирует новый токен
func (g *TokenGenerator) generateToken(userID, clientID uuid.UUID, tokenType entity.TokenType, scopes []string, duration time.Duration) (*entity.Token, error) {
	log.Debug("generating token",
		zap.String("user_id", userID.String()),
		zap.String("client_id", clientID.String()),
		zap.String("token_type", string(tokenType)),
		zap.Duration("duration", duration),
	)

	value, err := g.generateRandomString(g.config.TokenLength)
	if err != nil {
		log.Error("failed to generate random string for token",
			zap.String("user_id", userID.String()),
			zap.String("client_id", clientID.String()),
			zap.Error(err),
		)
		return nil, err
	}

	now := time.Now()
	token := &entity.Token{
		ID:        uuid.New(),
		UserID:    userID,
		ClientID:  clientID,
		Type:      tokenType,
		Value:     value,
		Scopes:    scopes,
		ExpiresAt: now.Add(duration),
		CreatedAt: now,
		IsRevoked: false,
	}

	log.Debug("token generated successfully",
		zap.String("token_id", token.ID.String()),
		zap.Time("expires_at", token.ExpiresAt),
	)

	return token, nil
}

// generateRandomString генерирует случайную строку заданной длины
func (g *TokenGenerator) generateRandomString(length int) (string, error) {
	log.Debug("generating random string",
		zap.Int("length", length),
	)

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		log.Error("failed to generate random bytes",
			zap.Int("length", length),
			zap.Error(err),
		)
		return "", err
	}

	randomString := base64.URLEncoding.EncodeToString(bytes)[:length]
	log.Debug("random string generated successfully",
		zap.Int("length", len(randomString)),
	)

	return randomString, nil
}
