# syntax=docker/dockerfile:1

FROM golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b AS build

WORKDIR /src

COPY go.mod go.sum ./
COPY internal/logger ./internal/logger
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/sealed-shim ./cmd/shim

FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

RUN apk add --no-cache ca-certificates

COPY --from=build /out/sealed-shim /usr/local/bin/sealed-shim
COPY deploy/shim/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/sealed-shim

EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
