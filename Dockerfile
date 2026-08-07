FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sentinel_shield/ sentinel_shield/
COPY sentinel-shield.yml .
COPY pyproject.toml .

RUN pip install -e .

EXPOSE 8080
EXPOSE 9090

ENTRYPOINT ["sentinel-shield"]
CMD ["--help"]
