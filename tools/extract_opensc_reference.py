#!/usr/bin/env python3
"""Extract only the SM routines into a temporary test translation unit.
The original LGPL sources remain outside this project. No firmware uses them.
"""
import pathlib
import re
import sys
source = pathlib.Path(sys.argv[1]).read_text()
names = ['gen_init_key', 'verify_init_key', 'construct_data_tlv', 'construct_le_tlv', 'construct_mac_tlv',
         'construct_mac_tlv_case1', 'encode_apdu',
         'epass2003_check_response_mac_and_sw', 'decrypt_response',
         'epass2003_sm_unwrap_apdu']
chunks = []
for name in names:
    pattern = r'static int\s+\n?' + re.escape(name) + r'\('
    m = re.search(pattern, source)
    if not m:
        raise SystemExit(f'missing OpenSC function: {name}')
    start = source.index('{', m.end())
    # These routines have balanced braces in their comments and strings.
    level = 1
    end = start + 1
    while level:
        level += (source[end] == '{') - (source[end] == '}')
        end += 1
    chunks.append(source[m.start():end])
pathlib.Path(sys.argv[2]).write_text('\n\n'.join(chunks))
