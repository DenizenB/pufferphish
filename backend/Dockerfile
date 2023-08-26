FROM python:3

WORKDIR /app

ADD requirements.txt .
RUN apt update \
    && apt install -y chromium xvfb \
    && apt clean all \
    && pip install --disable-pip-version-check --no-cache-dir -r requirements.txt

# Run undetected_chromedriver patcher and store the resulting driver at /app/undetected_chromedriver
RUN python -c 'from undetected_chromedriver import Patcher; p = Patcher(); p.auto(); import os; os.rename(p.executable_path, "/app/undetected_chromedriver")'

ADD src/ .
RUN pytest

EXPOSE 8080
CMD ["python", "app.py"]
