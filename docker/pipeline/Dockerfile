# Use Ubuntu as the base image
FROM ubuntu:20.04 AS builder

# Set non-interactive mode for timezone configuration
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    gcc \
    g++ \
    libc6-dev \
    make \
    pkg-config \
    git \
    wget \
    gnupg \
    ca-certificates \
    sudo \
    netcat

# Install Go
RUN curl -fsSL https://golang.org/dl/go1.21.2.linux-amd64.tar.gz | tar -C /usr/local -xzf -

# Set Go environment variables
ENV PATH="/usr/local/go/bin:/go/bin:${PATH}"
ENV GOPATH="/go"
ENV GOBIN="/go/bin"

# Install buf
RUN wget https://github.com/bufbuild/buf/releases/download/v1.28.0/buf-Linux-x86_64 && \
    chmod +x buf-Linux-x86_64 && \
    mv buf-Linux-x86_64 /usr/local/bin/buf

# Install protoc-gen-go-grpc and protoc-gen-go
RUN GO111MODULE=off go get google.golang.org/grpc/cmd/protoc-gen-go-grpc && \
    GO111MODULE=off go get google.golang.org/protobuf/cmd/protoc-gen-go && \
    GO111MODULE=off go get -u golang.org/x/lint/golint && \
    GO111MODULE=off go get golang.org/x/tools/cmd/goimports

# Clean up
RUN apt-get clean && rm -rf /var/lib/apt/lists/*
