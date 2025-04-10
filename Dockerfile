# 使用基础镜像
FROM go-base:latest AS builder

WORKDIR /app

# 拷贝 Go 模块文件并下载依赖
COPY go.mod ./
RUN go mod download

# 拷贝源码并构建
COPY . .
RUN go build -o app main.go

# 最小化镜像（可选）
FROM alpine:3.18
WORKDIR /app
COPY --from=builder /app/app .

# .env 文件会通过 docker-compose 挂载
CMD ["./app"]
