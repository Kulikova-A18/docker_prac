FROM python:3.11-slim

WORKDIR /app
COPY . .
RUN rm Dockerfile
RUN apt update && apt upgrade -y
RUN apt install curl -y
RUN pip3 install requests
CMD ["bash", "entrypoint.sh"]
