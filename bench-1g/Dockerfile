# Dockerfile for bench-1g iperf3
# Build: docker build -t bench-1g-iperf3 .
# Use: docker run --rm --network host bench-1g-iperf3 iperf3 ...

FROM ghcr.io/networkstatic/iperf3:latest

# Optional: Add any custom tools/scripts
# COPY run-*.sh /usr/local/bin/
# RUN chmod +x /usr/local/bin/run-*.sh

ENTRYPOINT ["iperf3"]