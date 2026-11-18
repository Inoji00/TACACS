ARG PYTHON_IMAGE=python:3.12-slim-trixie
FROM ${PYTHON_IMAGE} AS build
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
COPY migrations ./migrations
RUN pip install --no-cache-dir --prefix=/install . \
    && chmod -R a+rX /install /build/migrations

FROM ${PYTHON_IMAGE}
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade zlib1g \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' zlib1g)" \
       ge '1:1.3.dfsg+really1.3.1-1+deb13u1' \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --create-home tacacs \
    && install -d -o 10001 -g 10001 -m 0700 /run/tnac-alerts
COPY --from=build /install /usr/local
COPY --from=build /build/migrations /app/migrations
USER 10001:10001
WORKDIR /app
RUN test -r /app/migrations/001_initial.sql \
    && python -c 'from importlib.resources import files; files("tacacs_appliance").joinpath("console", "console.js").read_bytes()'
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 TZ=Asia/Ho_Chi_Minh PGTZ=UTC
CMD ["python", "-m", "tacacs_appliance"]
