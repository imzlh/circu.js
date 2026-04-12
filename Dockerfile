FROM alpine:latest AS builder
RUN apk add build-base cmake curl-dev libffi-dev ninja --update-cache
WORKDIR /circu.js
COPY . .
RUN cmake -B build -G Ninja -DUSE_EXTERNAL_FFI=ON -DCMAKE_BUILD_TYPE=Release && cmake --build build

FROM alpine:latest
RUN apk add libstdc++ libcurl libffi tini --no-cache
COPY --from=builder /circu.js/build/cjs /bin/cjs
COPY ./docker/entry.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 755 /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["tini", "--", "docker-entrypoint.sh"]
CMD ["cjs"]
