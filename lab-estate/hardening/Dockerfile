# LAB-only scanner image. Not the pack artifact.
# Installs Lynis (GPLv3) and OpenSCAP + SSG (LGPL/BSD) inside this
# isolated lab container. Never copied into the pack Dockerfile.
# Isolated compose network only. No public targets. No CIS profiles.
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        lynis \
        openscap-scanner \
        openscap-utils \
        ssg-base \
        ssg-debian \
        openssh-server \
        vsftpd \
        procps \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/run/sshd /drop /opt/lab-scan \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords yes/' /etc/ssh/sshd_config \
    && printf 'listen=YES\nanonymous_enable=YES\nlocal_enable=YES\nwrite_enable=YES\n' > /etc/vsftpd.conf

COPY run-host.sh /opt/lab-scan/run-host.sh
RUN chmod 0755 /opt/lab-scan/run-host.sh

# Stay up so the operator can exec the scanners. No published ports.
CMD ["sleep", "infinity"]
