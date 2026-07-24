"""Compare two black-box config captures without a protocol schema.

The comparison indexes frames by their observed top-level field number and
occurrence, recursively descends length-delimited values that are themselves
well-formed protobuf messages, and prints only changed leaves. Printable byte
runs are shown as strings, which makes a controlled name change visible without
assigning meanings to any field in advance.

Usage: python compare_config.py before.json after.json [top_field]
"""

import json
import sys
from collections import defaultdict
from pathlib import Path


def read_varint(data, offset):
    value = 0
    shift = 0
    while offset < len(data) and shift < 64:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, offset
        shift += 7
    raise ValueError("invalid varint")


def parse_message(data):
    fields = []
    offset = 0
    try:
        while offset < len(data):
            tag, offset = read_varint(data, offset)
            number = tag >> 3
            wire = tag & 7
            if number == 0:
                raise ValueError("field zero")
            if wire == 0:
                value, offset = read_varint(data, offset)
            elif wire == 1:
                value = data[offset : offset + 8]
                if len(value) != 8:
                    raise ValueError("truncated fixed64")
                offset += 8
            elif wire == 2:
                length, offset = read_varint(data, offset)
                value = data[offset : offset + length]
                if len(value) != length:
                    raise ValueError("truncated bytes")
                offset += length
            elif wire == 5:
                value = data[offset : offset + 4]
                if len(value) != 4:
                    raise ValueError("truncated fixed32")
                offset += 4
            else:
                raise ValueError("unsupported wire type")
            fields.append((number, wire, value))
    except ValueError:
        return None
    return fields


def display_bytes(value):
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return value.hex()
    if text and all(character.isprintable() for character in text):
        return repr(text)
    return value.hex()


def flatten_message(data, prefix, leaves):
    fields = parse_message(data)
    if fields is None:
        leaves[prefix] = ("bytes", display_bytes(data))
        return
    occurrences = defaultdict(int)
    for number, wire, value in fields:
        occurrence = occurrences[number]
        occurrences[number] += 1
        path = f"{prefix}.{number}[{occurrence}]"
        if wire == 0:
            leaves[path] = ("varint", str(value))
        elif wire in (1, 5):
            leaves[path] = (f"fixed{len(value) * 8}", value.hex())
        else:
            nested = parse_message(value)
            if nested:
                flatten_message(value, path, leaves)
            else:
                leaves[path] = ("bytes", display_bytes(value))


def capture_leaves(path, only_top=None):
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    occurrences = defaultdict(int)
    leaves = {}
    for encoded in document["frames"]:
        frame = bytes.fromhex(encoded)
        fields = parse_message(frame)
        if fields is None or len(fields) != 1:
            raise ValueError(f"{path}: frame is not one top-level field")
        number, wire, value = fields[0]
        occurrence = occurrences[number]
        occurrences[number] += 1
        if only_top is not None and number != only_top:
            continue
        prefix = f"{number}[{occurrence}]"
        if wire == 0:
            leaves[prefix] = ("varint", str(value))
        elif wire in (1, 5):
            leaves[prefix] = (f"fixed{len(value) * 8}", value.hex())
        else:
            flatten_message(value, prefix, leaves)
    return leaves


def main():
    if len(sys.argv) < 3:
        raise SystemExit("usage: compare_config.py before.json after.json [top_field]")
    only_top = int(sys.argv[3]) if len(sys.argv) > 3 else None
    before = capture_leaves(sys.argv[1], only_top)
    after = capture_leaves(sys.argv[2], only_top)
    changed = 0
    for path in sorted(set(before) | set(after)):
        old = before.get(path)
        new = after.get(path)
        if old != new:
            changed += 1
            print(f"{path}: {old!r} -> {new!r}")
    if changed == 0:
        print("no structural leaf differences")
    else:
        print(f"{changed} changed leaf/leaves")


if __name__ == "__main__":
    main()
