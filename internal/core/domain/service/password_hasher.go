package service

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"go.uber.org/zap"
	"golang.org/x/crypto/argon2"
)

// PasswordHasherConfig конфигурация для хеширования паролей
type PasswordHasherConfig struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultConfig возвращает конфигурацию по умолчанию
func DefaultConfig() *PasswordHasherConfig {
	return &PasswordHasherConfig{
		Memory:      64 * 1024, // 64MB
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// PasswordHasher сервис для хеширования паролей
type PasswordHasher struct {
	config *PasswordHasherConfig
	logger *zap.Logger
}

// NewPasswordHasher создает новый экземпляр PasswordHasher
func NewPasswordHasher(config *PasswordHasherConfig) *PasswordHasher {
	if config == nil {
		config = DefaultConfig()
	}

	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}

	return &PasswordHasher{
		config: config,
		logger: logger,
	}
}

// HashPassword хеширует пароль используя Argon2id
func (h *PasswordHasher) HashPassword(password string) (string, error) {
	h.logger.Debug("hashing password",
		zap.Uint32("memory", h.config.Memory),
		zap.Uint32("iterations", h.config.Iterations),
		zap.Uint8("parallelism", h.config.Parallelism),
	)

	salt := make([]byte, h.config.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		h.logger.Error("failed to generate salt", zap.Error(err))
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		h.config.Iterations,
		h.config.Memory,
		h.config.Parallelism,
		h.config.KeyLength,
	)

	encodedHash := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		h.config.Memory,
		h.config.Iterations,
		h.config.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	h.logger.Debug("password hashed successfully")
	return encodedHash, nil
}

// VerifyPassword проверяет соответствие пароля хешу
func (h *PasswordHasher) VerifyPassword(password, encodedHash string) (bool, error) {
	h.logger.Debug("verifying password")

	params, salt, hash, err := h.decodeHash(encodedHash)
	if err != nil {
		h.logger.Error("failed to decode hash", zap.Error(err))
		return false, fmt.Errorf("decode hash: %w", err)
	}

	otherHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	match := subtle.ConstantTimeCompare(hash, otherHash) == 1
	h.logger.Debug("password verification completed", zap.Bool("match", match))

	return match, nil
}

// decodeHash декодирует хеш в параметры, соль и хеш
func (h *PasswordHasher) decodeHash(encodedHash string) (*PasswordHasherConfig, []byte, []byte, error) {
	h.logger.Debug("decoding hash")

	var version int
	var memory uint32
	var iterations uint32
	var parallelism uint8

	_, err := fmt.Sscanf(encodedHash, "$argon2id$v=%d$m=%d,t=%d,p=%d$",
		&version, &memory, &iterations, &parallelism)
	if err != nil {
		h.logger.Error("invalid hash format", zap.Error(err))
		return nil, nil, nil, fmt.Errorf("invalid hash format: %w", err)
	}

	parts := make([]string, 5)
	for i := range parts {
		parts[i] = encodedHash
		encodedHash = encodedHash[len(parts[i]):]
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		h.logger.Error("failed to decode salt", zap.Error(err))
		return nil, nil, nil, fmt.Errorf("decode salt: %w", err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		h.logger.Error("failed to decode hash", zap.Error(err))
		return nil, nil, nil, fmt.Errorf("decode hash: %w", err)
	}

	params := &PasswordHasherConfig{
		Memory:      memory,
		Iterations:  iterations,
		Parallelism: parallelism,
		SaltLength:  uint32(len(salt)),
		KeyLength:   uint32(len(hash)),
	}

	h.logger.Debug("hash decoded successfully",
		zap.Int("version", version),
		zap.Uint32("memory", memory),
		zap.Uint32("iterations", iterations),
		zap.Uint8("parallelism", parallelism),
	)

	return params, salt, hash, nil
}
