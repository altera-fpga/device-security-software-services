FROM ubuntu:18.04

RUN apt update && \
    apt install -y sudo wget nano zip unzip curl aria2 lsb-release build-essential g++-aarch64-linux-gnu git cmake

RUN mkdir bkpprogrammer
WORKDIR bkpprogrammer
CMD ["/bin/bash"]
