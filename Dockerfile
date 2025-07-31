FROM golang:alpine AS builder

ENV GO111MODULE=on \
    CGO_ENABLED=0

WORKDIR /build
COPY . .
RUN go mod tidy
RUN go build --ldflags "-s -w -extldflags -static" -o main .

FROM alpine:latest

WORKDIR /www

COPY --from=builder /build/main /www/
# config, database are dev only
COPY --from=builder /build/config/ /www/config/
COPY --from=builder /build/database/ /www/database/
COPY --from=builder /build/public/ /www/public/
COPY --from=builder /build/storage/ /www/storage/
COPY --from=builder /build/resources/ /www/resources/
# Note: .env is not copied - use environment variables in docker-compose.yml

ENTRYPOINT ["/www/main"]
