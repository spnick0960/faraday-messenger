# Faraday relay — ephemeral ciphertext mailbox. No plaintext, no disk archive.
FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/relay ./cmd/relay

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/relay /app/relay
COPY web /app/web
ENV PORT=43147
ENV FARADAY_WEB=/app/web
ENV FARADAY_DATA=/tmp/faraday-mailboxes.json
EXPOSE 43147
USER nonroot
ENTRYPOINT ["/app/relay"]
