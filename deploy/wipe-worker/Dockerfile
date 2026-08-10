# syntax=docker/dockerfile:1

FROM golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/wipe-worker ./cmd/wipe-worker

FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

RUN apk add --no-cache ca-certificates

COPY --from=build /out/wipe-worker /usr/local/bin/wipe-worker
COPY scripts/vram_two_pass.py /usr/local/bin/vram_two_pass.py

ENV WIPE_LISTEN=0.0.0.0:19001
ENV WIPE_CUDA_HELPER=/usr/local/bin/vram_two_pass.py

EXPOSE 19001

USER nobody
ENTRYPOINT ["/usr/local/bin/wipe-worker"]
