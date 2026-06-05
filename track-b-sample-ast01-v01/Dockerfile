# Skill-CTF Track B 检测引擎 — 超精简镜像
# 从 alpine 手动安装 Python，精确控制体积
FROM alpine:3.20

# 安装 Python3 并清理缓存
RUN apk add --no-cache python3 && \
    # 删除不必要的 Python 模块
    rm -rf /usr/lib/python3.12/test/ && \
    rm -rf /usr/lib/python3.12/idlelib/ && \
    rm -rf /usr/lib/python3.12/turtledemo/ && \
    rm -rf /usr/lib/python3.12/lib2to3/ && \
    rm -rf /usr/lib/python3.12/distutils/ && \
    rm -rf /usr/lib/python3.12/ensurepip/ && \
    rm -rf /usr/lib/python3.12/pydoc_data/ && \
    rm -rf /usr/lib/python3.12/__pycache__/ && \
    find /usr/lib/python3.12 -name "*.pyc" -delete && \
    find /usr/lib/python3.12 -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null && \
    # 删除 pip 等工具
    rm -f /usr/bin/pip* /usr/bin/pydoc* /usr/bin/idle* /usr/bin/2to3* && \
    rm -rf /root/.cache/ /var/cache/apk/*

WORKDIR /app

COPY engine/engine.py /app/engine.py

ENTRYPOINT ["python3", "/app/engine.py"]