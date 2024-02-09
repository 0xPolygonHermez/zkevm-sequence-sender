# CONTAINER FOR BUILDING BINARY
FROM golang:1.21 AS build

# INSTALL DEPENDENCIES
RUN go install github.com/gobuffalo/packr/v2/packr2@v2.8.3
COPY go.mod go.sum /src/
RUN cd /src && go mod download

# BUILD BINARY
COPY cmd /src/cmd
COPY sequencesender /src/sequencesender
COPY log /src/log
COPY Makefile version.go config/environments/local/local.node.config.toml /src/
RUN cd /src && make build


# CONTAINER FOR RUNNING BINARY
FROM alpine:3.19.0

COPY --from=build /src/dist/zkevm-seqsender /app/zkevm-seqsender
COPY --from=build /src/local.node.config.toml /app/sample.config.toml

ARG USER=seqsender
ENV HOME /home/$USER
RUN adduser -D $USER
USER $USER
WORKDIR $HOME

EXPOSE 8124
CMD ["/bin/sh", "-c", "/app/zkevm-seqsender run"]
