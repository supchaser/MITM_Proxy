# ====== Build Stage ======
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Копируем зависимости и скачиваем их
COPY go.mod ./
RUN go mod download

# Копируем исходный код и собираем бинарник
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o mitm-proxy ./cmd/proxy/main.go

# ====== Runtime Stage ======
FROM alpine:latest

WORKDIR /app

# Копируем бинарник из builder-стадии
COPY --from=builder /app/mitm-proxy .

# Копируем сертификаты и скрипты генерации
COPY --from=builder /app/certs /app/certs

# Даем права на выполнение скриптов (если они нужны)
RUN chmod +x /app/certs/gen_ca.sh /app/certs/gen_cert.sh

# Пробрасываем порты:
# - 8080 для прокси
# - 8000 для Web-интерфейса
EXPOSE 8080
EXPOSE 8000

# Запускаем прокси
CMD ["./mitm-proxy"]
