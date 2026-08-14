#!/bin/sh
# One HTTP transaction. busybox `nc -lk -p 8080 -e /echo/serve.sh` execs a fresh
# copy of this per inbound connection, with the socket on stdin/stdout.
#
# The request is drained before the response is written: replying without reading
# would let nc close the socket while the client is still sending, which shows up
# on Windows as an RST that discards the already-queued response.
CR=$(printf '\r')
while IFS= read -r line; do
    case "$line" in
        "" | "$CR") break ;;
    esac
done

BODY='QPN-ECHO-OK'
printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
    "${#BODY}" "$BODY"
