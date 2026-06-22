# Synthetic Track B platform sample — not built in CI.
FROM python:3.12.8-slim-bookworm@sha256:8859bd6ca943079262c27e38b7119cdacede77c463139a15651dd340087a6cc9

RUN groupadd --system skillsec && useradd --system --gid skillsec --create-home --home-dir /home/skillsec skillsec

WORKDIR /app
COPY --chown=skillsec:skillsec engine/engine.py /app/engine.py
# Sample ast01 variant 2
ENV PYTHONUNBUFFERED=1
USER skillsec
ENTRYPOINT ["python", "/app/engine.py"]
