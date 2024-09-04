#!/usr/bin/env bash

kind load docker-image quay.io/brancz/kube-rbac-proxy:local
kind load docker-image quay.io/brancz/prometheus-example-app:v0.5.0
kind load docker-image quay.io/brancz/prometheus-example-app:v0.4.0
kind load docker-image quay.io/brancz/krp-curl:v0.0.2
