# 构建上下文是仓库根目录。只编译跳板，不包含任何密库代码。
FROM rust:1.95-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p vault-relay \
 && cp target/release/vault-relay /vault-relay

# 只导出可执行文件：docker build --target bin --output out .
FROM scratch AS bin
COPY --from=build /vault-relay /

FROM alpine:3.22
RUN adduser -D -H -u 10470 relay \
 && install -d -o relay -g relay -m 700 /var/lib/vault-relay
COPY --from=build /vault-relay /usr/local/bin/vault-relay
USER relay
VOLUME /var/lib/vault-relay
EXPOSE 7470
ENTRYPOINT ["vault-relay"]
CMD ["serve"]
