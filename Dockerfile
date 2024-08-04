FROM ubuntu:latest
LABEL authors="smj"

ENTRYPOINT ["top", "-b"]