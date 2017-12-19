#!/usr/bin/env bash

echo "$ kube-rbac-proxy -h" > _output/help.txt
_output/linux/amd64/kube-rbac-proxy -h 2>> _output/help.txt
exit 0
