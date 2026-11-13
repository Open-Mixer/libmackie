#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# The version and the soname have one definition each, and every copy must agree with it:
#   ARM 1  VERSION is the version: mackie.h's MACKIE_VERSION_STRING, the spec's Version and the top
#          entry of debian/changelog say the same;
#   ARM 2  MACKIE_ABI of mackie.h is the spec's %global abi and the N of the libmackieN package,
#          and debian/libmackie-dev depends on that package by that name.
# It reads files, not git, so it also runs from a release tarball. A planted copy with the spec at
# another version runs first and must be refused, so the check cannot pass vacuously.
#
# Exit 0 conforms, 1 an arm found an offence, 2 the planted copy was not refused (NOT A RESULT).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)

check() {
	t=$1 bad=0
	ver=$(cat "$t/VERSION" 2>/dev/null)
	hdr=$t/include/mackie/mackie.h spec=$t/packaging/libmackie.spec
	hver=$(sed -n 's/^#define MACKIE_VERSION_STRING "\(.*\)"/\1/p' "$hdr")
	abi=$(sed -n 's/^#define MACKIE_ABI  *\([0-9][0-9]*\)$/\1/p' "$hdr")
	if [ -z "$ver" ] || [ -z "$abi" ]; then
		echo "  could not read VERSION or MACKIE_ABI"
		return 1
	fi
	spec_ver=$(sed -n 's/^Version: *//p' "$spec")
	spec_abi=$(sed -n 's/^%global abi  *//p' "$spec")
	deb_ver=$(sed -n '1s/^[^ ]* (\([^)]*\)).*/\1/p' "$t/debian/changelog")
	deb_ver=${deb_ver%%~*}   # an untagged build stamps ~git<sha> on the top entry,
	deb_ver=${deb_ver%%+*}   # a staged one +git<sha>
	deb_abi=$(sed -n 's/^Package: libmackie\([0-9][0-9]*\)$/\1/p' "$t/debian/control")

	[ "$hver" = "$ver" ] || { echo "  ARM 1: mackie.h says $hver, VERSION says $ver"; bad=1; }
	[ "$spec_ver" = "$ver" ] || { echo "  ARM 1: the spec says Version $spec_ver, VERSION says $ver"; bad=1; }
	[ "$deb_ver" = "$ver" ] || { echo "  ARM 1: debian/changelog says $deb_ver, VERSION says $ver"; bad=1; }
	[ "$spec_abi" = "$abi" ] || { echo "  ARM 2: the spec's abi is $spec_abi, MACKIE_ABI is $abi"; bad=1; }
	[ "$deb_abi" = "$abi" ] || { echo "  ARM 2: debian/control builds libmackie$deb_abi, MACKIE_ABI is $abi"; bad=1; }
	p="libmackie$abi"
	[ -f "$t/debian/$p.install" ] || { echo "  ARM 2: debian/$p.install is missing"; bad=1; }
	grep -q "^Depends:.* $p (= \${binary:Version})" "$t/debian/control" ||
		{ echo "  ARM 2: libmackie-dev does not depend on $p"; bad=1; }
	return $bad
}

plant() { # dir [sed-expression file]
	mkdir -p "$1/include/mackie" "$1/packaging" "$1/debian"
	cp "$ROOT/VERSION" "$1/"
	cp "$ROOT/include/mackie/mackie.h" "$1/include/mackie/"
	cp "$ROOT/packaging/libmackie.spec" "$1/packaging/"
	cp "$ROOT/debian/changelog" "$ROOT/debian/control" "$ROOT"/debian/*.install "$1/debian/"
	[ $# -lt 3 ] || sed -i "$2" "$1/$3"
}

tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT
plant "$tmp/bad" 's/^Version: .*/Version: 9.9.9/' packaging/libmackie.spec
if check "$tmp/bad" >/dev/null; then
	echo "NOT A RESULT: a tree with the spec at 9.9.9 was not refused"
	exit 2
fi
check "$ROOT" || exit 1
echo "conformance-packaging: VERSION $(cat "$ROOT/VERSION"), soname $(sed -n 's/^#define MACKIE_ABI  *//p' "$ROOT/include/mackie/mackie.h") agree everywhere"
