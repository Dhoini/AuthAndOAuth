module AuthAndOauth

go 1.24

require (
	// Веб-фреймворк и HTTP-компоненты
	github.com/go-chi/chi/v5 v5.0.12
	github.com/go-chi/cors v1.2.1
	github.com/go-chi/render v1.0.3
	github.com/go-chi/jwtauth/v5 v5.3.0
	github.com/go-chi/httprate v0.8.0

	// База данных и миграции
	github.com/jackc/pgx/v5 v5.5.5
	github.com/jmoiron/sqlx v1.3.5
	github.com/golang-migrate/migrate/v4 v4.17.0

	// Кеширование
	github.com/redis/go-redis/v9 v9.4.0
	github.com/go-redsync/redsync/v4 v4.11.0

	// Kafka
	github.com/segmentio/kafka-go v0.4.47

	// OAuth2 и аутентификация
	github.com/go-oauth2/oauth2/v4 v4.5.2
	github.com/golang-jwt/jwt/v5 v5.2.0
	golang.org/x/crypto v0.20.0
	github.com/google/uuid v1.6.0

	// Валидация и работа со структурами
	github.com/go-playground/validator/v10 v10.18.0
	github.com/mitchellh/mapstructure v1.5.0

	// Конфигурация
	github.com/spf13/viper v1.18.2

	// Логирование
	go.uber.org/zap v1.27.0
	github.com/rs/zerolog v1.32.0

	// Метрики и мониторинг
	github.com/prometheus/client_golang v1.18.0
	go.opentelemetry.io/otel v1.24.0
	go.opentelemetry.io/otel/trace v1.24.0
	go.opentelemetry.io/otel/exporters/jaeger v1.17.0

	// Утилиты
	github.com/stretchr/testify v1.8.4 // косвенная зависимость
	github.com/shopspring/decimal v1.3.1
)

require (
	// Зависимости транзитивных пакетов
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	github.com/klauspost/compress v1.17.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/lib/pq v1.10.9 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/pelletier/go-toml/v2 v2.1.1 // indirect
	github.com/pierrec/lz4/v4 v4.1.16 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/sagikazarmark/locafero v0.4.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.11.0 // indirect
	github.com/spf13/cast v1.6.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/exp v0.0.0-20240222234643-814bf88cf225 // indirect
	golang.org/x/sync v0.6.0 // indirect
	golang.org/x/sys v0.17.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)