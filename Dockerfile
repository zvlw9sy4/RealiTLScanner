FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
# Build with trimpath to reduce binary size and remove local path info
RUN go build -trimpath -ldflags='-s -w' -o RealiTLScanner .

FROM alpine:latest
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=build /src/RealiTLScanner .
# Set default timezone to UTC explicitly
ENV TZ=UTC
# Run as non-root user for better security
RUN adduser -D -u 1000 scanner && chown scanner:scanner /app/RealiTLScanner
USER scanner
ENTRYPOINT ["./RealiTLScanner"]
