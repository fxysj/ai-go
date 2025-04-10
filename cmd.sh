 curl -X POST http://localhost:8080/chat \\n  -H "Content-Type: application/json" \\n  -d '{"question": "介绍一下GPT-4的能力"}'

 docker build -f Dockerfile.base -t go-base:latest .

 make base      # 1. 构建基础镜像
 make up-d      # 2. 构建并启动整个服务