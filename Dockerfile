FROM golang:1.24-alpine AS build
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /meridian .

FROM alpine:3.21
RUN adduser -D -u 10001 meridian
USER meridian
COPY --from=build /meridian /usr/local/bin/meridian
EXPOSE 8080
ENTRYPOINT ["meridian"]
