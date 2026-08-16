# Start from Ubuntu
FROM ubuntu:22.04

# This is the key fix:
# 1. Set frontend to non-interactive to prevent all install prompts
# 2. Set a default TimeZone (TZ) for the tzdata package
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# --- System-level setup (as root) ---
RUN apt update && apt install -y \
    locales \
    build-essential \
    vim \
    git \
    sudo \
    chrpath \
    cpio \
    debianutils \
    diffstat \
    file \
    gawk \
    gcc \ 
    iputils-ping \
    libacl1 \
    liblz4-tool \ 
    locales \
    python3 \
    python3-git \
    python3-jinja2 \ 
    python3-pexpect \
    python3-pip \
    python3-subunit \
    socat \
    texinfo \ 
    unzip \
    wget \
    xz-utils \ 
    zstd \
    && rm -rf /var/lib/apt/lists/* \
    && locale-gen en_US.UTF-8 \
    && update-locale LANG=en_US.UTF-8

# --- User setup (using build args) ---
ARG UNAME=dev
ARG UID=1000
ARG GID=1000

# Create the group and user
RUN groupadd -g $GID $UNAME && \
    useradd -u $UID -g $GID -m -s /bin/bash $UNAME

# Add the user to the sudo group
RUN usermod -aG sudo $UNAME

# --- THIS IS THE NEW LINE ---
# Allow this user to run sudo without a password
RUN echo "$UNAME ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
# ----------------------------

# --- Set default user ---
USER $UNAME
WORKDIR /home/$UNAME
ENV PS1="[\u@\h \W]\$ "