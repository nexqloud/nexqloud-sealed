# syntax=docker/dockerfile:1

FROM golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b AS build

WORKDIR /src

COPY go.mod go.sum ./
COPY internal/logger ./internal/logger
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/wipe-worker ./cmd/wipe-worker \
 && sha256sum /out/wipe-worker | awk '{print "sha256:" $1}' > /out/wipe-worker.commitment

FROM nvidia/cuda:12.6.3-runtime-ubuntu24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/wipe-worker /usr/local/bin/wipe-worker
COPY --from=build /out/wipe-worker.commitment /usr/local/share/nexqloud/wipe-worker.commitment
COPY scripts/vram_two_pass.py /usr/local/bin/vram_two_pass.py
RUN chmod 755 /usr/local/bin/wipe-worker /usr/local/bin/vram_two_pass.py

ENV WIPE_LISTEN=0.0.0.0:19001
ENV WIPE_MODE=cuda
ENV WIPE_CUDA_HELPER=/usr/local/bin/vram_two_pass.py

EXPOSE 19001

ENTRYPOINT ["/usr/local/bin/wipe-worker"]
