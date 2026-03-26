FROM golang:1.23 AS builder
WORKDIR /app
COPY main.go .
RUN CGO_ENABLED=0 go build -o unix-upstream main.go

FROM gcr.io/distroless/static:nonroot-amd64
COPY --from=builder /app/unix-upstream /usr/local/bin/unix-upstream
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/unix-upstream"]
