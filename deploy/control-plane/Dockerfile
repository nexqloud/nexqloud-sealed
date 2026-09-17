# syntax=docker/dockerfile:1
#
# Control plane for federated cryptographic erasure (invention 3):
# the destruction coordinator, the destruction aggregator, and the federated
# key-derivation registry.
#
# None of these needs a TEE: the coordinator orchestrates, the aggregator binds
# evidence, the registry records which operators hold key material. They never see
# key material or plaintext, which is why they can live on ordinary cloud hosts.
#
# One image carries all three roles so they version and ship together; pick the role
# as the first argument (see entrypoint.sh):
#
#   docker run --rm sealed-control-plane registry    --addr :7001 --mongo "$MONGO_URL"
#   docker run --rm sealed-control-plane coordinator --addr :7003 --registry … --aggregator … \
#                                                    --operators operator-a=http://…,operator-b=http://…
#   docker run --rm sealed-control-plane aggregator  --addr :7004 --substrate-key-hex … --rekor …

FROM golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b AS build

WORKDIR /src

COPY go.mod go.sum ./
COPY internal/logger ./internal/logger
RUN go mod download

COPY . .
RUN set -eux; \
    for target in sealed-registry:./cmd/registry destruction-coordinator:./cmd/destruction-coordinator destruction-aggregator:./cmd/destruction-aggregator; do \
      name="${target%%:*}"; pkg="${target#*:}"; \
      CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o "/out/${name}" "${pkg}"; \
      sha256sum "/out/${name}" | awk '{print "sha256:" $1}' > "/out/${name}.commitment"; \
    done

FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

RUN apk add --no-cache ca-certificates curl tini \
 && adduser -D -u 10001 -s /sbin/nologin controlplane

COPY --from=build /out/sealed-registry /out/destruction-coordinator /out/destruction-aggregator /usr/local/bin/
COPY --from=build /out/*.commitment /usr/local/share/nexqloud/
COPY deploy/control-plane/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh /usr/local/bin/sealed-registry /usr/local/bin/destruction-coordinator /usr/local/bin/destruction-aggregator

USER 10001

# The roles listen on their conventional ports; override with -addr as needed.
EXPOSE 7001
EXPOSE 7003
EXPOSE 7004

ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
