#!/bin/sh

licRes=$(
	for file in $(find . -type f -iname '*.go' ! -path '*/vendor/*'); do
		head -n5 "${file}" | grep -Eq "(Copyright|generated|GENERATED)" || printf "  %s\n" "${file}"
	done
)
if [ -n "${licRes}" ]; then
	printf "license header checking failed:\n%s\n" "${licRes}"
	exit 255
fi
