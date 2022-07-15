#!/usr/bin/env bash

set -ue #x
cd "$(dirname "$0")"

export LC_NUMERIC=C

mapfile="$1"
destdir="$2"


for f in $(awk -F: '{print $1}' "$mapfile" | sort -u); do
	test -f "$f"

	[[ $f == *valgrind* ]] && continue

	mkdir -p "$destdir"/$(dirname "$f")

	for l in $(find $(dirname "$f") -exec readlink -nf {} ';' -exec echo ":{}" ';' | grep "$f" | awk -F: '{print $2}'); do

		cp -avi "$l" "$destdir"/$(dirname "$l")
	done

	if test -f "/usr/lib/debug/$f"; then
		! test -f "$destdir/$f-unstripped.so"
		echo "$f" + "/usr/lib/debug/$f" '->' "$destdir/$f-unstripped.so"
		eu-unstrip "$f" "/usr/lib/debug/$f" -o "$destdir/$f-unstripped.so"
	fi
done