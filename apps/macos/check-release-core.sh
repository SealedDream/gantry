#!/bin/sh
# Refuse a core built with test hooks (BASTION_TEST_HOOKS=1 ./build-core.sh) before it is bundled.
# Links a C probe against Generated/lib/libbastion_ffi.a and asks the core `test_hooks_build()`.
# Exit 0: release core. Exit 1: test-hooks core, or the answer could not be read.
#   sh apps/macos/check-release-core.sh [libbastion_ffi.a [headers dir]]
set -eu
cd "$(dirname "$0")"
LIB="${1:-Generated/lib/libbastion_ffi.a}"
HEADERS="${2:-Generated/headers}"
[ -f "$LIB" ] || { echo "missing $LIB: run ./build-core.sh" >&2; exit 1; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
cat > "$T/probe.c" <<'C'
#include <stdio.h>
#include "bastion_ffiFFI.h"
int main(void) {
    RustCallStatus status = {0};
    int8_t hooks = uniffi_bastion_ffi_fn_func_test_hooks_build(&status);
    if (status.code != 0) { fprintf(stderr, "test_hooks_build call failed (%d)\n", status.code); return 2; }
    printf("%d\n", hooks);
    return 0;
}
C
clang -I "$HEADERS" -o "$T/probe" "$T/probe.c" "$LIB" -framework Security -framework SystemConfiguration -framework CoreFoundation -framework IOKit -liconv
answer="$("$T/probe")" || { echo "could not ask the core whether it has test hooks" >&2; exit 1; }
if [ "$answer" != 0 ]; then
  echo "REFUSED: $LIB was built with test hooks (BASTION_TEST_HOOKS=1). Rebuild with ./build-core.sh before bundling." >&2
  exit 1
fi
echo "release core: no test hooks"
