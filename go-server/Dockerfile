FROM golang:1.24.3-alpine

WORKDIR /app

COPY go-server/go.mod .
RUN go mod download

COPY go-server/ .

EXPOSE 8080

CMD ["go", "run", "main.go"]