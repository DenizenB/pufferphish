FROM python:3

RUN apt update \
    && apt install -y chromium \
    && apt clean all \
    && pip install requests flask pytest mitmproxy undetected-chromedriver selenium-wire

WORKDIR /app
ADD src/ .

RUN pytest

EXPOSE 8080
CMD ["python", "app.py"]
