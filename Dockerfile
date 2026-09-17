FROM gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2

ARG TARGETARCH
ARG SOURCE_REVISION=unknown
ARG SOURCE_SHA256=unknown
LABEL org.opencontainers.image.title="whatap-network-agent" \
      org.opencontainers.image.source="https://github.com/whatap/agentkubenetwork" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      io.whatap.source.sha256="${SOURCE_SHA256}"

COPY dist/linux/${TARGETARCH}/agentkubenetwork /usr/local/bin/agentkubenetwork
USER 0:0
ENTRYPOINT ["/usr/local/bin/agentkubenetwork"]
CMD ["-source=ebpf", "-output-mode=windows", "-export=tagcount"]
