FROM golang:alpine3.10

LABEL maintainer="fuskovic"

RUN mkdir /app && \
    apk update && \
    apk add git && \
    apk add curl && \
    apk add make && \
    apk add gcc && \
    apk add libc-dev && \
    apk add libpcap-dev && \
    apk add openssl

WORKDIR /app

RUN git clone https://github.com/fuskovic/rem-cap

WORKDIR /app/rem-cap/

RUN make binaries

CMD ./remcap_server -p 80