package valueobject

import (
	"fmt"
	"net/mail"
	"strings"
	"go.uber.org/zap"
)

var log *zap.Logger

func init() {
	var err error
	log, err = zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
}

// Email представляет email адрес
type Email struct {
	address string
}

// NewEmail создает новый Email
func NewEmail(address string) (*Email, error) {
	log.Debug("creating new email",
		zap.String("address", address),
	)

	address = strings.TrimSpace(address)
	if address == "" {
		log.Error("email address is empty")
		return nil, fmt.Errorf("email address cannot be empty")
	}

	if _, err := mail.ParseAddress(address); err != nil {
		log.Error("invalid email format",
			zap.String("address", address),
			zap.Error(err),
		)
		return nil, fmt.Errorf("invalid email format: %w", err)
	}

	log.Debug("email created successfully",
		zap.String("address", address),
	)

	return &Email{address: address}, nil
}

// String возвращает строковое представление email
func (e Email) String() string {
	return e.address
}

// Equals сравнивает два email адреса
func (e Email) Equals(other Email) bool {
	return strings.EqualFold(e.address, other.address)
}

// Address возвращает email адрес
func (e Email) Address() string {
	return e.address
}

// MarshalJSON реализует json.Marshaler
func (e Email) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", e.address)), nil
}

// UnmarshalJSON реализует json.Unmarshaler
func (e *Email) UnmarshalJSON(data []byte) error {
	var address string
	if err := json.Unmarshal(data, &address); err != nil {
		log.Error("failed to unmarshal email",
			zap.Error(err),
		)
		return err
	}

	email, err := NewEmail(address)
	if err != nil {
		log.Error("failed to create email from json",
			zap.String("address", address),
			zap.Error(err),
		)
		return err
	}

	*e = *email
	return nil
} 