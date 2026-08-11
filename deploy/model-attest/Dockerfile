# syntax=docker/dockerfile:1

FROM golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b AS build

WORKDIR /src

COPY go.mod go.sum ./
COPY internal/logger ./internal/logger
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/model-attest ./cmd/model-attest \
 && sha256sum /out/model-attest | awk '{print "sha256:" $1}' > /out/model-attest.commitment

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/model-attest /usr/local/bin/model-attest
COPY --from=build /out/model-attest.commitment /usr/local/share/nexqloud/model-attest.commitment

ENV MODEL_ATTEST_LISTEN=0.0.0.0:19002

EXPOSE 19002

ENTRYPOINT ["/usr/local/bin/model-attest"]
