package valueobject

import (
	"fmt"
	"unicode"
	"go.uber.org/zap"
)

// PasswordPolicy определяет политику паролей
type PasswordPolicy struct {
	MinLength         int
	MaxLength         int
	RequireUpper      bool
	RequireLower      bool
	RequireDigit      bool
	RequireSpecial    bool
	MinSpecialChars   int
	DisallowedChars   []rune
	DisallowedStrings []string
}

// DefaultPasswordPolicy возвращает политику по умолчанию
func DefaultPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:         8,
		MaxLength:         72, // Максимальная длина для bcrypt
		RequireUpper:      true,
		RequireLower:      true,
		RequireDigit:      true,
		RequireSpecial:    true,
		MinSpecialChars:   1,
		DisallowedChars:   []rune{' '},
		DisallowedStrings: []string{"password", "123456", "qwerty"},
	}
}

// Password представляет пароль
type Password struct {
	hash     string
	policy   *PasswordPolicy
	hasher   *service.PasswordHasher
}

// NewPassword создает новый Password
func NewPassword(plaintext string, policy *PasswordPolicy) (*Password, error) {
	log.Debug("creating new password",
		zap.Int("length", len(plaintext)),
	)

	if policy == nil {
		policy = DefaultPasswordPolicy()
	}

	if err := validatePassword(plaintext, policy); err != nil {
		log.Error("password validation failed",
			zap.Error(err),
		)
		return nil, err
	}

	hasher := service.NewPasswordHasher(nil)
	hash, err := hasher.HashPassword(plaintext)
	if err != nil {
		log.Error("failed to hash password",
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	log.Debug("password created successfully")

	return &Password{
		hash:     hash,
		policy:   policy,
		hasher:   hasher,
	}, nil
}

// NewPasswordFromHash создает Password из существующего хеша
func NewPasswordFromHash(hash string) *Password {
	log.Debug("creating password from hash")
	return &Password{
		hash:     hash,
		policy:   DefaultPasswordPolicy(),
		hasher:   service.NewPasswordHasher(nil),
	}
}

// Verify проверяет соответствие пароля хешу
func (p Password) Verify(plaintext string) bool {
	log.Debug("verifying password")

	match, err := p.hasher.VerifyPassword(plaintext, p.hash)
	if err != nil {
		log.Error("failed to verify password",
			zap.Error(err),
		)
		return false
	}

	log.Debug("password verification completed",
		zap.Bool("match", match),
	)
	return match
}

// Hash возвращает хеш пароля
func (p Password) Hash() string {
	return p.hash
}

// validatePassword проверяет пароль на соответствие политике
func validatePassword(password string, policy *PasswordPolicy) error {
	log.Debug("validating password against policy")

	if len(password) < policy.MinLength {
		log.Error("password too short",
			zap.Int("length", len(password)),
			zap.Int("min_length", policy.MinLength),
		)
		return fmt.Errorf("password must be at least %d characters long", policy.MinLength)
	}

	if len(password) > policy.MaxLength {
		log.Error("password too long",
			zap.Int("length", len(password)),
			zap.Int("max_length", policy.MaxLength),
		)
		return fmt.Errorf("password must not exceed %d characters", policy.MaxLength)
	}

	var (
		hasUpper    bool
		hasLower    bool
		hasDigit    bool
		specialChar int
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			specialChar++
		}

		for _, disallowed := range policy.DisallowedChars {
			if char == disallowed {
				log.Error("password contains disallowed character",
					zap.String("char", string(char)),
				)
				return fmt.Errorf("password contains disallowed character: %c", char)
			}
		}
	}

	if policy.RequireUpper && !hasUpper {
		log.Error("password requires uppercase character")
		return fmt.Errorf("password must contain at least one uppercase letter")
	}

	if policy.RequireLower && !hasLower {
		log.Error("password requires lowercase character")
		return fmt.Errorf("password must contain at least one lowercase letter")
	}

	if policy.RequireDigit && !hasDigit {
		log.Error("password requires digit")
		return fmt.Errorf("password must contain at least one digit")
	}

	if policy.RequireSpecial && specialChar < policy.MinSpecialChars {
		log.Error("password requires special characters",
			zap.Int("required", policy.MinSpecialChars),
			zap.Int("found", specialChar),
		)
		return fmt.Errorf("password must contain at least %d special characters", policy.MinSpecialChars)
	}

	lowered := strings.ToLower(password)
	for _, disallowed := range policy.DisallowedStrings {
		if strings.Contains(lowered, strings.ToLower(disallowed)) {
			log.Error("password contains disallowed string",
				zap.String("disallowed", disallowed),
			)
			return fmt.Errorf("password contains disallowed string: %s", disallowed)
		}
	}

	log.Debug("password validation successful")
	return nil
} 