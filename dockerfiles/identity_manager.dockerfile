ARG IMAGE_ARCH=amd64
FROM balenalib/${IMAGE_ARCH}-ubuntu:bionic

ENV DEBIAN_FRONTEND noninteractive
ENV CRYPTOGRAPHY_DONT_BUILD_RUST 1
ENV APP_NAME identity_manager
ENV MESSAGING_USER messaging
ENV APP_UID 1001

ENV SRC_BASE_PATH ./applications/${APP_NAME}
WORKDIR /application/${APP_NAME}/depends

COPY ${SRC_BASE_PATH}/depends/os_packages os_packages
COPY ${SRC_BASE_PATH}/depends/requirements.txt requirements.txt

RUN apt-get update && \
    cat ./os_packages | xargs apt-get install -y

RUN pip3 install --upgrade pip && \
    pip3 install -r requirements.txt

WORKDIR /application/${APP_NAME}/src
COPY ${SRC_BASE_PATH}/src .
COPY ./shared_libs/idlib ./idlib

CMD balena-idle
