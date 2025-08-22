# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install system dependencies
RUN apk add --no-cache git

# Copy dependency files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main cmd/api/main.go

# Production stage
FROM alpine:latest

# Install HTTPS ca-certificates
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binary from build step
COPY --from=builder /app/main .

# Create directory for logs
RUN mkdir -p /app/logs

# Export port
EXPOSE 8080

# Run the application
CMD ["./main"]
