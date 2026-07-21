FROM golang:1.24-alpine AS build
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY cmd/meridian-agent ./cmd/meridian-agent
RUN CGO_ENABLED=0 go build -o /meridian-agent ./cmd/meridian-agent

FROM alpine:3.21
RUN adduser -D -u 10001 meridian
USER meridian
COPY --from=build /meridian-agent /usr/local/bin/meridian-agent
ENTRYPOINT ["meridian-agent"]
