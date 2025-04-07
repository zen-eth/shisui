FROM golang:1.24.2 AS builder

WORKDIR /app

COPY . .

RUN make shisui


FROM ubuntu:24.04

COPY --from=builder /app/build/bin/shisui /usr/local/bin/app

EXPOSE 8545 9009/udp

ENTRYPOINT [ "app" ]