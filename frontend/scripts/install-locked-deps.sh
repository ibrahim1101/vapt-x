#!/bin/sh
# Retry transient registry failures; every attempt keeps the same frozen lockfile.
set -eu
for attempt in 1 2 3; do
    if yarn install --frozen-lockfile --ignore-scripts --non-interactive --registry https://registry.npmjs.org; then
        exit 0
    fi
    if [ "$attempt" -eq 3 ]; then
        exit 1
    fi
    sleep 2
done
