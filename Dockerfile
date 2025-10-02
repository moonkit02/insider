ARG GO_VERSION=latest
FROM golang:${GO_VERSION} AS builder
WORKDIR /build
COPY . /build/
RUN go mod download
RUN make build-release

FROM alpine
WORKDIR /opt/insider
COPY --from=builder /build/insider /opt/insider/insider
COPY entrypoint.sh /opt/insider/entrypoint.sh
RUN chmod +x /opt/insider/entrypoint.sh
ENTRYPOINT ["/opt/insider/entrypoint.sh"]