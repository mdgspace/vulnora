FROM golang:1.24.4-alpine

WORKDIR /app

COPY go-server/go.mod .
RUN go mod download

COPY auth-server/ .

EXPOSE 8081

CMD ["go", "run", "."]