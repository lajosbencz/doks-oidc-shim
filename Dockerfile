
# scratch / alpine
ARG DISTRO=scratch

# versions
ARG GO_VERSION=1.26
ARG ALPINE_VERSION=3.22

# target
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG BINARY_NAME=doks-oidc-shim


FROM alpine:${ALPINE_VERSION} AS stage-certs
RUN apk add --no-cache ca-certificates && \
    addgroup -S shim && adduser -S shim -G shim


FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS stage-build
ARG TARGETOS
ARG TARGETARCH
ARG BINARY_NAME
WORKDIR /app
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify
COPY *.go ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o "/${BINARY_NAME}" .


FROM alpine:${ALPINE_VERSION} AS final-alpine


FROM scratch AS final-scratch


FROM final-${DISTRO}
ARG BINARY_NAME
COPY --from=stage-certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=stage-certs /etc/passwd /etc/passwd
COPY --from=stage-certs /etc/group /etc/group
COPY --from=stage-build "/${BINARY_NAME}" "/${BINARY_NAME}"
USER shim
ENTRYPOINT ["/${BINARY_NAME}"]
