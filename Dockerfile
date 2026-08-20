FROM node:22-alpine AS frontend
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26.5-alpine AS backend
WORKDIR /src
COPY go.mod go.sum ./
ARG GOPROXY=https://goproxy.cn,direct
RUN GOPROXY=${GOPROXY} go mod download
COPY . ./
COPY --from=frontend /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -o /out/opencode-proxy ./cmd/server

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=backend /out/opencode-proxy ./opencode-proxy
COPY --from=backend /src/web/dist ./web/dist
RUN addgroup -S -g 10001 relaydesk && adduser -S -D -H -u 10001 -G relaydesk relaydesk \
    && mkdir -p /data \
    && chown -R relaydesk:relaydesk /data /app
ENV WEB_DIR=/app/web/dist DATABASE_PATH=/data/app.db PORT=8080
EXPOSE 8080
VOLUME ["/data"]
USER 10001:10001
CMD ["/app/opencode-proxy"]
