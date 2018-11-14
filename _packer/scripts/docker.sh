#!/bin/sh -x

curl https://install.terraform.io/ptfe/stable | bash -s no-proxy install-docker-only
apt-mark hold docker-ce
