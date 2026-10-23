#!/bin/sh
set -eu
exec /usr/bin/python3 -I -B "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/manage.py" --remove "$@"
