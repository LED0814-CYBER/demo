# 以 python:3.12-slim-bullseye 这个官方镜像作为基础
FROM python:3.12-slim-bullseye

# 不生成 .pyc 字节码缓存文件，并且 Python 标准输出不做缓冲，日志立刻打印出来
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# 设置工作目录
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openjdk-11-jre-headless \
        gcc \
        g++ \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/storage/uploads /app/storage/reports /app/storage/logs /app/data/phunter_soot_cache /app/data/lib_pickles_cache /app/outputs/raw

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
