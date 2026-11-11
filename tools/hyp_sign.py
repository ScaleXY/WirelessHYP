#!/usr/bin/env python3
"""Exercise UART0 JSON lines and verify a raw P-256 digest signature.
Install only pyserial and cryptography. PIN input is hidden and never printed.
"""
import argparse
import getpass
import json
import secrets
import sys
import time

import serial
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def receive(port, deadline):
    while time.monotonic() < deadline:
        line = port.readline()
        if not line:
            continue
        try:
            obj = json.loads(line.decode('ascii'))
        except (ValueError, UnicodeDecodeError):
            continue  # ROM/boot noise is deliberately ignored.
        if isinstance(obj, dict):
            return obj
    raise TimeoutError('timed out waiting for firmware')


def send(port, obj):
    port.write((json.dumps(obj, separators=(',', ':')) + '\n').encode('ascii'))
    port.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('port', help='UART USB-serial bridge port, e.g. /dev/cu.usbserial-...')
    parser.add_argument('--baud', type=int, default=115200)
    parser.add_argument('--set-pin', action='store_true', help='provision/replace PIN via hidden prompt (clears fatal latch)')
    parser.add_argument('--timeout', type=float, default=30)
    parser.add_argument('--count', type=int, default=1)
    args = parser.parse_args()
    if args.count < 1:
        parser.error('--count must be positive')
    # Avoid deliberate reset toggles: UART bridge DTR/RTS may reset DevKitC.
    port = serial.Serial(port=None, baudrate=args.baud, timeout=0.25)
    port.dtr = False
    port.rts = False
    port.port = args.port
    with port:
        deadline = time.monotonic() + args.timeout
        if args.set_pin:
            pin = getpass.getpass('Token PIN (stored in board NVS): ')
            send(port, {'id': 0, 'op': 'set_pin', 'pin': pin})
            del pin
        # Firmware may already have emitted ready before the port was opened.
        # pubkey obtains it lazily as well; ready remains the preferred event.
        send(port, {'id': 1, 'op': 'pubkey'})
        point = None
        while point is None:
            msg = receive(port, deadline)
            if 'fatal' in msg:
                raise RuntimeError(msg.get('error', 'pin_rejected'))
            if msg.get('ready') or (msg.get('id') == 1 and 'qx' in msg):
                point = (int(msg['qx'], 16), int(msg['qy'], 16))
            elif msg.get('id') in (0, 1) and 'error' in msg:
                raise RuntimeError(msg['error'])
        public_key = ec.EllipticCurvePublicNumbers(*point, ec.SECP256R1()).public_key()
        for request_id in range(2, 2 + args.count):
            digest = secrets.token_bytes(32)
            send(port, {'id': request_id, 'digest': '0x' + digest.hex()})
            deadline = time.monotonic() + args.timeout
            while True:
                msg = receive(port, deadline)
                if 'fatal' in msg:
                    raise RuntimeError(msg.get('error', 'pin_rejected'))
                if msg.get('id') != request_id:
                    continue
                if 'error' in msg:
                    raise RuntimeError(msg['error'])
                r, s = int(msg['r'], 16), int(msg['s'], 16)
                if not (1 <= r < ORDER and 1 <= s <= ORDER // 2):
                    raise AssertionError('invalid scalar or high-s signature')
                public_key.verify(utils.encode_dss_signature(r, s), digest,
                                  ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                print(f'PASS id={request_id}: signature verified, low-s, firmware {msg["ms"]:.3f} ms')
                break


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        sys.exit(1)
