FROM golang:1.15-alpine AS builder
RUN apk --no-cache add ca-certificates
WORKDIR /build

# Download dependencies first to take advantage of layer caching
COPY go.* ./
RUN go mod download

# Copy source code and build application
COPY ./ ./
RUN go build -o detector

# Copy the binary from the builder image, set it as entrypoint, include provided logfile
FROM scratch
USER 1000:1000
ADD dd_ad_takehome.csv ./
COPY --from=builder /build/detector /detector
ENTRYPOINT ["/detector"] 
CMD [ "-f", "dd_ad_takehome.csv" ]