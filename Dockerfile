# Multi-stage build for ezrec
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o ezrec main.go

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates git curl bash

# Create app user
RUN adduser -D -s /bin/bash ezrec

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/ezrec .

# Copy configuration files and scripts
COPY profiles/ ./profiles/
COPY templates/ ./templates/
COPY wordlists/ ./wordlists/
COPY install-tools.sh ./

# Make scripts executable
RUN chmod +x ezrec install-tools.sh

# Install external tools
RUN ./install-tools.sh

# Create output directory
RUN mkdir -p /app/out && chown ezrec:ezrec /app/out

# Switch to app user
USER ezrec

# Set PATH to include Go binaries
ENV PATH="/home/ezrec/go/bin:${PATH}"

# Expose volume for output
VOLUME ["/app/out"]

# Default command
ENTRYPOINT ["./ezrec"]
CMD ["--help"]