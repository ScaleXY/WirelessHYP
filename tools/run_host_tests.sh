#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p tests/.build
if [ -n "${OPENSSL_PREFIX:-}" ]; then
    crypto_prefix=$OPENSSL_PREFIX
elif [ -d /opt/homebrew/opt/openssl@3 ]; then
    crypto_prefix=/opt/homebrew/opt/openssl@3
elif command -v pkg-config >/dev/null && pkg-config --exists openssl; then
    crypto_prefix=$(pkg-config --variable=prefix openssl)
else
    echo 'Set OPENSSL_PREFIX to an existing OpenSSL development installation.' >&2
    exit 1
fi
# OpenSSL is the test-only reference crypto provider; firmware uses IDF PSA.
cc -std=c11 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
    -Icomponents/epass2003/include -Icomponents/ccid_host/include \
    -Icomponents/signer_proto/include -Imain -I"$crypto_prefix/include" \
    components/epass2003/crypto.c components/epass2003/des.c components/epass2003/sm.c components/epass2003/pkcs15.c components/epass2003/card.c components/epass2003/low_s.c \
    components/ccid_host/ccid_frame.c components/ccid_host/t1.c components/signer_proto/signer_proto.c \
    main/service.c main/web_logic.c tests/test_main.c -L"$crypto_prefix/lib" -lcrypto -o tests/.build/test_main
./tests/.build/test_main
ref_default=tests/.opensc
ref_root=${OPENSC_REFERENCE:-$ref_default}
if [ -f "$ref_root/src/libopensc/card-epass2003.c" ]; then
    python3 tools/extract_opensc_reference.py "$ref_root/src/libopensc/card-epass2003.c" tests/.build/opensc_sm.inc
    cc -std=c11 -g -fsanitize=address,undefined -Icomponents/epass2003/include \
        -Itests/.build -I"$crypto_prefix/include" tests/test_reference.c \
        components/epass2003/crypto.c components/epass2003/des.c components/epass2003/sm.c components/epass2003/pkcs15.c -L"$crypto_prefix/lib" -lcrypto \
        -o tests/.build/test_reference
    ./tests/.build/test_reference
else
    echo 'SKIP original-source comparison: set OPENSC_REFERENCE to OpenSC 3856d69 checkout.'
fi
python3 -m py_compile tools/hyp_sign.py tools/extract_opensc_reference.py
cc -std=c11 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
    -Imain -Icomponents/signer_proto/include main/web_logic.c main/json_out.c \
    components/signer_proto/signer_proto.c tests/test_web.c -o tests/.build/test_web
./tests/.build/test_web
