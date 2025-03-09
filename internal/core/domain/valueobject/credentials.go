package valueobject

import (
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
)

// Credentials представляет учетные данные пользователя
type Credentials struct {
	Email    Email
	Password Password
}

// NewCredentials создает новые учетные данные
func NewCredentials(email string, password string) (*Credentials, error) {
	log.Debug("creating new credentials",
		zap.String("email", email),
	)

	emailObj, err := NewEmail(email)
	if err != nil {
		log.Error("failed to create email for credentials",
			zap.String("email", email),
			zap.Error(err),
		)
		return nil, fmt.Errorf("invalid email: %w", err)
	}

	passwordObj, err := NewPassword(password, nil)
	if err != nil {
		log.Error("failed to create password for credentials",
			zap.String("email", email),
			zap.Error(err),
		)
		return nil, fmt.Errorf("invalid password: %w", err)
	}

	log.Debug("credentials created successfully",
		zap.String("email", emailObj.String()),
	)

	return &Credentials{
		Email:    *emailObj,
		Password: *passwordObj,
	}, nil
}

// NewCredentialsWithPolicy создает новые учетные данные с указанной политикой паролей
func NewCredentialsWithPolicy(email string, password string, policy *PasswordPolicy) (*Credentials, error) {
	log.Debug("creating new credentials with custom policy",
		zap.String("email", email),
	)

	emailObj, err := NewEmail(email)
	if err != nil {
		log.Error("failed to create email for credentials with policy",
			zap.String("email", email),
			zap.Error(err),
		)
		return nil, fmt.Errorf("invalid email: %w", err)
	}

	passwordObj, err := NewPassword(password, policy)
	if err != nil {
		log.Error("failed to create password for credentials with policy",
			zap.String("email", email),
			zap.Error(err),
		)
		return nil, fmt.Errorf("invalid password: %w", err)
	}

	log.Debug("credentials with policy created successfully",
		zap.String("email", emailObj.String()),
	)

	return &Credentials{
		Email:    *emailObj,
		Password: *passwordObj,
	}, nil
}

// Verify проверяет учетные данные
func (c Credentials) Verify(password string) bool {
	log.Debug("verifying credentials",
		zap.String("email", c.Email.String()),
	)

	match := c.Password.Verify(password)

	log.Debug("credentials verification completed",
		zap.String("email", c.Email.String()),
		zap.Bool("match", match),
	)

	return match
}

// MarshalJSON реализует json.Marshaler
func (c Credentials) MarshalJSON() ([]byte, error) {
	log.Debug("marshaling credentials",
		zap.String("email", c.Email.String()),
	)

	return []byte(fmt.Sprintf(`{"email":%q,"password_hash":%q}`,
		c.Email.String(),
		c.Password.Hash(),
	)), nil
}

// UnmarshalJSON реализует json.Unmarshaler
func (c *Credentials) UnmarshalJSON(data []byte) error {
	log.Debug("unmarshaling credentials")

	var raw struct {
		Email       string `json:"email"`
		PasswordHash string `json:"password_hash"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		log.Error("failed to unmarshal credentials",
			zap.Error(err),
		)
		return err
	}

	email, err := NewEmail(raw.Email)
	if err != nil {
		log.Error("failed to create email from json",
			zap.String("email", raw.Email),
			zap.Error(err),
		)
		return err
	}

	c.Email = *email
	c.Password = *NewPasswordFromHash(raw.PasswordHash)

	log.Debug("credentials unmarshaled successfully",
		zap.String("email", c.Email.String()),
	)

	return nil
} 