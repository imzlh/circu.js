FROM alpine:latest AS builder
RUN apk add build-base cmake curl-dev libffi-dev --update-cache
WORKDIR /circu.js
COPY . .
RUN make distclean && USE_EXTERNAL_FFI=ON make

FROM alpine:latest
RUN apk add libstdc++ libcurl libffi tini --no-cache
COPY --from=builder /circu.js/build/tjs /bin/tjs
COPY --from=builder /circu.js/examples /examples
COPY ./docker/entry.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 755 /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["tini", "--", "docker-entrypoint.sh"]
CMD ["run", "/examples/hello_world.js"]
