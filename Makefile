BASE_IMAGE_NAME=go-base
SERVICE_IMAGE_NAME=awesome-go-app
COMPOSE_FILE=docker-compose.yaml

# 构建基础镜像
base:
	docker build -f Dockerfile.base -t $(BASE_IMAGE_NAME):latest .

# 构建服务镜像
build:
	docker-compose -f $(COMPOSE_FILE) build

# 启动服务
up:
	docker-compose -f $(COMPOSE_FILE) up --build

# 后台启动
up-d:
	docker-compose -f $(COMPOSE_FILE) up --build -d

# 停止服务
down:
	docker-compose -f $(COMPOSE_FILE) down

# 查看日志
logs:
	docker-compose -f $(COMPOSE_FILE) logs -f
