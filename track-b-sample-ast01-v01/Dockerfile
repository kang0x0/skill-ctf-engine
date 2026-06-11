FROM python:3.12.8-slim-bookworm

RUN groupadd --system skillsec && useradd --system --gid skillsec --create-home --home-dir /home/skillsec skillsec

WORKDIR /app
COPY --chown=skillsec:skillsec engine/engine.py /app/engine.py

# 预创建输出目录，确保 skillsec 用户始终可写
RUN mkdir -p /output && chown skillsec:skillsec /output && chmod 755 /output

ENV PYTHONUNBUFFERED=1
USER skillsec
ENTRYPOINT ["python", "/app/engine.py"]