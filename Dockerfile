FROM --platform=linux/amd64 golang:1.23 as builder

WORKDIR /app

COPY . .
RUN go env -w  GOPROXY=https://goproxy.cn,direct
# RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build ./cmd/shisui/main.go
RUN make shisui


FROM  --platform=linux/amd64 ubuntu:22.04

COPY --from=builder /app/build/bin/shisui /usr/local/bin/app

EXPOSE 8545 9009/udp

ENTRYPOINT [ "app" ]