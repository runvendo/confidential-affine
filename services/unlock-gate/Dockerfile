# unlock-gate: static Go binary, rootless, distroless.
# The unlock page gates passphrase entry behind in-browser Tinfoil attestation
# verification. The verifier is a self-contained JS bundle that MUST be embedded
# into the binary (the enclave is ReadonlyRootfs/distroless/nonroot and never
# fetches it from a CDN). Stage 1 builds that bundle so `//go:embed` can pick it
# up in stage 2.

# Stage 1: build the browser verifier bundle (verifier/dist/verifier.bundle.js).
FROM node:22-bookworm AS verifier
WORKDIR /verifier
COPY verifier/package.json verifier/package-lock.json* ./
RUN npm ci || npm install
COPY verifier/src ./src
RUN npm run build

# Stage 2: compile the Go gate with the verifier bundle embedded.
FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
# Provide the freshly built bundle at the path main.go embeds.
COPY --from=verifier /verifier/dist/verifier.bundle.js ./verifier/dist/verifier.bundle.js
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /unlock-gate .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /unlock-gate /unlock-gate
USER nonroot
EXPOSE 3010 9090
ENTRYPOINT ["/unlock-gate"]
