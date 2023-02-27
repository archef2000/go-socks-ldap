ARG base_image=golang:1.20

FROM ${base_image} as build

ENV GO111MODULE=on

RUN apt update &&  apt install ca-certificates libgnutls30 -y

RUN mkdir -p /go/src

WORKDIR /go/src

COPY . .

RUN set -xe \
    && go mod tidy \
    && go mod vendor -v \
    && go build -ldflags "-linkmode external -extldflags -static" -a main.go

FROM scratch
COPY config.yaml /config.yaml
COPY --from=build /go/src/main /main

ENTRYPOINT ["/main"]

LABEL image.name="go-socks-ldap" \
      image.socks_version="5" \
      image.description="Provides a go Socks5 server with LDAP auth."
