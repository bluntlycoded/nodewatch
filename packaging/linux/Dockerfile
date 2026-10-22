# Linux build environment for the agent and master (nodewatch-server)
# binaries.
#
# A PyInstaller binary links against the glibc it was built with and runs
# on that version or newer. AlmaLinux 8 has glibc 2.28, so the output runs
# on RHEL/Rocky/Alma 8+, Ubuntu 20.04+, Debian 10+ and Amazon Linux 2023.
# A Debian-based python image would raise that floor to 2.31+ and drop
# RHEL 8, which is the common case on long-lived servers.
#
#   docker build -t nodewatch-agent-build -f packaging/linux/Dockerfile .
#   docker run --rm -v "$PWD:/src" nodewatch-agent-build                       # agent
#   docker run --rm -v "$PWD:/src" nodewatch-agent-build \
#       python3.12 packaging/build_server.py                                  # master
#
# Add --platform linux/amd64 or linux/arm64 to pick the architecture.
FROM almalinux:8

# python3.12-tkinter: the agent's join window. On a headless server it is
# never loaded, so the missing X libraries there do not matter.
RUN dnf install -y python3.12 python3.12-pip python3.12-devel python3.12-tkinter binutils \
 && dnf clean all

# Dependencies install at build time of the image, not of the binary, so
# repeated builds do not refetch them.
COPY agent/requirements.txt /tmp/agent-requirements.txt
COPY api/requirements.txt /tmp/api-requirements.txt
COPY probe/requirements.txt /tmp/probe-requirements.txt
COPY packaging/requirements-build.txt /tmp/requirements-build.txt
RUN python3.12 -m pip install --no-cache-dir \
      -r /tmp/agent-requirements.txt -r /tmp/api-requirements.txt \
      -r /tmp/probe-requirements.txt -r /tmp/requirements-build.txt

WORKDIR /src
CMD ["python3.12", "packaging/build_agent.py"]
