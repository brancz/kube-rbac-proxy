#!/usr/bin/env bash

echo "$ kube-rbac-proxy -h" > _output/help.txt
_output/kube-rbac-proxy -h >> _output/help.txt
exit 0
