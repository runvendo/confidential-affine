# unlock-gate: static Go binary, rootless, distroless.
FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /unlock-gate .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /unlock-gate /unlock-gate
USER nonroot
EXPOSE 3010 9090
ENTRYPOINT ["/unlock-gate"]
