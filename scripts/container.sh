#!/usr/bin/env bash

set -euo pipefail

# move into base directory, in case this script is not executed via `make container`
cd "$(dirname "$0")/.." || exit 1

BRANCH=$(git branch --show-current)
TAG=gluon:${BRANCH}

if [ "$(command -v podman)" ]
then
	podman build -t "${TAG}" .
	podman run -it --rm --userns=keep-id --volume="$(pwd):/gluon" "${TAG}"
elif [ "$(command -v docker)" ]
then
	docker build -t "${TAG}" .
	docker run -it --rm --volume="$(pwd):/gluon" "${TAG}"
else
	1>&2 echo "Please install either podman or docker. Exiting" >/dev/null
	exit 1
fi

