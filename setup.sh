#!/bin/bash
set -e  # Stop on first error

echo "🚀 Setting up ContraQ Blockchain..."

# Update system
apt update -y && apt upgrade -y

# Install dependencies
apt install -y curl git unzip tar ufw

# Install Go
GO_VERSION="1.22.0"
cd ~
wget -q "https://go.dev/dl/go$GO_VERSION.linux-amd64.tar.gz"
rm -rf /usr/local/go
tar -C /usr/local -xzf "go$GO_VERSION.linux-amd64.tar.gz"
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version

# Clone ContraQ
cd ~
git clone https://github.com/JoshWallStreet/ContraQ.git
cd ContraQ

# Install Go dependencies
go mod tidy

# Build the blockchain node
go build -o contraq-node

# Start the blockchain node
./contraq-node &

echo "✅ ContraQ Blockchain is now running!"
echo "Use 'curl -X GET http://localhost:8080/blockchain' to test."
