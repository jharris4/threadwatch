# Built by the Supervisor from the folder bin/push-ha-addon.sh assembles
# in /addons: this folder's files beside the package, the vendored
# sniffer, the entrypoint and requirements.txt from the repository, and a
# REVISION naming the commit.
ARG BUILD_FROM=python:3.12-slim
FROM ${BUILD_FROM}
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY threadwatch/ threadwatch/
COPY vendor/ vendor/
COPY bin/threadwatch bin/threadwatch
COPY REVISION run.sh ./
CMD ["/app/run.sh"]
