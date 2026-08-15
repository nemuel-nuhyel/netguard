FROM python:3.12-alpine

WORKDIR /app

COPY generator.py .

RUN adduser -D -H netguard

USER netguard

HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD test -f /tmp/traffic-generator.health

CMD ["python", "generator.py"]
