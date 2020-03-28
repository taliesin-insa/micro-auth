# Dockerfile References: https://docs.docker.com/engine/reference/builder/

# Start from the latest golang base image
# Bad practice but anyway
FROM golang:latest AS builder

# Define directory
ADD src /src
WORKDIR /src/micro-auth

# Download dependancies (if you try to build your image without following lines you will see missing packages)
RUN go get -u github.com/gorilla/mux
RUN go get -u github.com/go-sql-driver/mysql
RUN go get -u github.com/dgrijalva/jwt-go

# Build all project statically (prevent some exec user process caused "no such file or directory" error)
ENV CGO_ENABLED=0
RUN go build -o main .

# Build the docker image from a lightest one (otherwise it weights more than 1Go)
FROM alpine:latest

# Expose port 12345 to the outside world
EXPOSE 8080

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy on the executive env
 COPY --from=builder /src/micro-auth/ .

# Command to run the executable
CMD ["./main"]

