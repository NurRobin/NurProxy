FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY nurproxy /usr/local/bin/nurproxy
EXPOSE 8080
VOLUME /data
ENTRYPOINT ["nurproxy"]
CMD ["--data-dir", "/data", "--port", "8080"]
