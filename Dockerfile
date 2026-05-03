
# scratch / alpine
ARG DISTRO=scratch

# versions
ARG GO_VERSION=1.26
ARG ALPINE_VERSION=3.22

# target
ARG TARGETOS=linux
ARG TARGETARCH=amd64


FROM alpine:${ALPINE_VERSION} AS stage-certs
RUN apk add --no-cache ca-certificates && \
    addgroup -S shim && adduser -S shim -G shim


FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS stage-build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /app
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify
COPY *.go ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /doks-oidc-shim .


FROM alpine:${ALPINE_VERSION} AS final-alpine


FROM scratch AS final-scratch


FROM final-${DISTRO}
COPY --from=stage-certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=stage-certs /etc/passwd /etc/passwd
COPY --from=stage-certs /etc/group /etc/group
COPY --from=stage-build /doks-oidc-shim /doks-oidc-shim
USER shim
ENTRYPOINT ["/doks-oidc-shim"]
