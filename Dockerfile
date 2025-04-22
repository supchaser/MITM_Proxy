FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod ./ 
RUN go mod download

COPY . /app/
RUN CGO_ENABLED=0 GOOS=linux go build -o app ./cmd/proxy/main.go

# --- Финальный образ ---
FROM alpine:latest

WORKDIR /root/

# Копируем бинарник приложения
COPY --from=builder /app/app /root/

# Копируем CA-файлы - ключ и сертификат
COPY --from=builder /app/certs/ca.crt /app/certs/ca.key /root/

# (если хотите, копируйте и скрипты - вдруг пригодятся)
COPY --from=builder /app/certs/gen_ca.sh /app/certs/gen_cert.sh /root/

EXPOSE 8080
EXPOSE 8000

CMD ["./app"]
