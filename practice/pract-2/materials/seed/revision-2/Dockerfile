FROM debian:12-slim

RUN apt-get update && apt-get install -y \
    build-essential cmake curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cmake -S . -B build && cmake --build build

CMD ["/app/build/release-agent"]
