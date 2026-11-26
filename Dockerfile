ARG PYTHON_IMAGE=python:3.12-alpine3.23
FROM ${PYTHON_IMAGE} AS build
WORKDIR /build
RUN pip install --no-cache-dir --prefix=/install --only-binary=:all: \
        'argon2-cffi>=23.1,<26' 'psycopg[binary,pool]>=3.2,<4' 'cryptography>=46,<51'
COPY pyproject.toml README.md ./
COPY src ./src
COPY migrations ./migrations
RUN pip install --no-cache-dir --prefix=/install --no-deps . \
    && chmod -R a+rX /install /build/migrations

FROM ${PYTHON_IMAGE}
RUN apk upgrade --no-cache \
    && apk add --no-cache tzdata \
    && addgroup -S -g 10001 tacacs \
    && adduser -S -D -u 10001 -G tacacs -h /home/tacacs tacacs \
    && mkdir -p /run/tnac-alerts /var/lib/tnac-syslog \
    && chown 10001:10001 /run/tnac-alerts /var/lib/tnac-syslog \
    && chmod 0700 /run/tnac-alerts /var/lib/tnac-syslog
COPY --from=build /install /usr/local
COPY --from=build /build/migrations /app/migrations
USER 10001:10001
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 TZ=Asia/Ho_Chi_Minh PGTZ=UTC
RUN test -r /app/migrations/001_initial.sql \
    && python -c 'import argon2, cryptography, psycopg; from importlib.resources import files; files("tacacs_appliance").joinpath("console", "console.js").read_bytes()'
CMD ["python", "-m", "tacacs_appliance"]
