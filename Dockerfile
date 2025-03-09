# Базовый образ для сборки
FROM golang:1.24 AS builder

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем go.mod и go.sum для кеширования зависимостей
COPY go.mod go.sum ./
RUN go mod download

# Копируем весь исходный код
COPY . .

# Собираем приложение с оптимизацией
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o auth-service ./cmd/server/main.go

# Финальный образ
FROM alpine:3.19

# Устанавливаем необходимые пакеты
RUN apk --no-cache add ca-certificates tzdata

# Устанавливаем рабочую директорию
WORKDIR /root/

# Копируем бинарный файл из builder
COPY --from=builder /app/auth-service .

# Копируем конфигурационные файлы
COPY configs/ ./configs/

# Указываем порт, который будет слушать сервис
EXPOSE 8080

# Команда для запуска сервиса
CMD ["./auth-service", "--config", "configs/prod.yaml"]