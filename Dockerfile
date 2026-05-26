# syntax=docker/dockerfile:1.6

# ---------- build stage ----------
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ballmerbuster ./cmd/ballmerbuster

# ---------- runtime stage ----------
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 -s /bin/bash bb

# Azure CLI (for `az login` credential pass-through)
RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash

COPY --from=build /out/ballmerbuster /usr/local/bin/ballmerbuster

USER bb
WORKDIR /data
ENTRYPOINT ["ballmerbuster"]
CMD ["--help"]
