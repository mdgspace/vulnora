FROM golang:1.24.4-alpine

WORKDIR /app

COPY go-server/go.mod .
RUN go mod download

COPY auth-server/ .

EXPOSE 3000

CMD ["go", "run", "."]