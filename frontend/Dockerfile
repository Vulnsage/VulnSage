FROM ubuntu:22.04

RUN sed -i 's|http://archive.ubuntu.com/ubuntu/|http://mirrors.aliyun.com/ubuntu/|g' /etc/apt/sources.list && \
    sed -i 's|http://security.ubuntu.com/ubuntu/|http://mirrors.aliyun.com/ubuntu/|g' /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y software-properties-common wget curl && \
    apt-get install -y git python3 netcat python3-venv python3-pip curl ca-certificates  && \
    apt-get clean

RUN python3 --version

RUN apt-get install -y vim
ADD https://astral.sh/uv/install.sh /uv-installer.sh
RUN sh /uv-installer.sh && rm /uv-installer.sh
ENV PATH="/root/.local/bin/:$PATH"

WORKDIR /app

COPY agentscope /app/agentscope
COPY pyproject.toml /app/pyproject.toml
COPY common /app/common
COPY configs /app/configs
COPY feeder /app/feeder
COPY prompting /app/prompting
COPY sage4j /app/sage4j
COPY sage4js /app/sage4js
COPY sage.py  /app/sage.py
COPY cli.py /app/cli.py

RUN uv sync