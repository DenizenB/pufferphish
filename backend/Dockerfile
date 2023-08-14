FROM python:3

RUN apt update \
    && apt install -y chromium xvfb \
    && apt clean all \
    && pip install --disable-pip-version-check --no-cache-dir requests flask pytest undetected-chromedriver selenium-wire xvfbwrapper

WORKDIR /app
ADD src/ .

RUN pytest

EXPOSE 8080
CMD ["python", "app.py"]
