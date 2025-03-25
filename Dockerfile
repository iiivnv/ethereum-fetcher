# 🏗 Stage 1: Build the Rust binary
FROM rust:1.84.1-bullseye as builder

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy actual source files
COPY . .

# Build the actual application
RUN cargo build --release

# 🚀 Stage 2: Create a minimal final image
# FROM debian:bullseye-slim
FROM rust:1.84.1-bullseye

# Set the working directory in the final image
WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/app/target/release/limeapi .

COPY wait-for-it.sh /app/wait-for-it.sh
RUN chmod +x /app/limeapi /app/wait-for-it.sh

ENV API_PORT=3000
ENV ETH_NODE_URL=https://mainnet.infura.io/v3/28d8b996e9174e82a7d049f4198deed1
ENV JWT_SECRET=1234567890
ENV DB_CONNECTION_URL=postgresql://postgres:postgres@db:5432/postgres

# Expose the port the server runs on (adjust if needed)
EXPOSE 3000

# Command to run the application
CMD ["./limeapi"]
