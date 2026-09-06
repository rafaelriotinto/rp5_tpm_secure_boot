#!/usr/bin/env python3
"""Build a flat device tree blob from a /proc/device-tree-style directory.

Enough of the FDT format (v17) for testing: header, empty mem-rsvmap, struct
block (BEGIN_NODE/PROP/END_NODE/END), strings block. Nodes are emitted in sorted
order; properties in sorted order; the 'name' pseudo-property that the kernel
exposes is dropped (it is not a real property in the blob).

Usage: fs2dtb.py <dir> <out.dtb> [--set path/to/prop=hexbytes ...]
                                 [--del path/to/prop-or-node ...]
"""
import os, struct, sys

FDT_MAGIC = 0xd00dfeed
BEGIN_NODE, END_NODE, PROP, NOP, END = 1, 2, 3, 4, 9

def load(d):
    tree = {}
    for root, dirs, files in os.walk(d):
        rel = os.path.relpath(root, d)
        rel = '' if rel == '.' else rel
        node = tree.setdefault(rel, {'props': {}, 'children': set()})
        for f in files:
            if f == 'name':
                continue
            with open(os.path.join(root, f), 'rb') as fh:
                node['props'][f] = fh.read()
        for c in dirs:
            crel = os.path.join(rel, c) if rel else c
            node['children'].add(crel)
            tree.setdefault(crel, {'props': {}, 'children': set()})
    return tree

def apply_edits(tree, sets, dels):
    for path in dels:
        if path in tree:            # a node
            for k in [k for k in tree if k == path or k.startswith(path + '/')]:
                del tree[k]
            parent = os.path.dirname(path)
            tree[parent]['children'].discard(path)
        else:                       # a property
            node, prop = os.path.dirname(path), os.path.basename(path)
            tree[node]['props'].pop(prop, None)
    for path, hexv in sets:
        node, prop = os.path.dirname(path), os.path.basename(path)
        tree.setdefault(node, {'props': {}, 'children': set()})
        tree[node]['props'][prop] = bytes.fromhex(hexv)

def build(tree):
    strings = bytearray(); stroff = {}
    def sid(name):
        if name not in stroff:
            stroff[name] = len(strings); strings.extend(name.encode() + b'\0')
        return stroff[name]
    st = bytearray()
    def align(b):
        while len(b) % 4: b.append(0)
    def emit(path):
        n = tree[path]
        name = os.path.basename(path) if path else ''
        st.extend(struct.pack('>I', BEGIN_NODE)); st.extend(name.encode() + b'\0'); align(st)
        for pn in sorted(n['props']):
            v = n['props'][pn]
            st.extend(struct.pack('>III', PROP, len(v), sid(pn))); st.extend(v); align(st)
        for c in sorted(n['children']):
            emit(c)
        st.extend(struct.pack('>I', END_NODE))
    emit('')
    st.extend(struct.pack('>I', END))
    hdr = 40; rsv = 16
    off_struct = hdr + rsv; off_strings = off_struct + len(st)
    total = off_strings + len(strings)
    header = struct.pack('>IIIIIIIIII', FDT_MAGIC, total, off_struct, off_strings, hdr,
                         17, 16, 0, len(strings), len(st))
    return header + b'\0' * rsv + bytes(st) + bytes(strings)

if __name__ == '__main__':
    d, out = sys.argv[1], sys.argv[2]
    sets, dels = [], []
    a = sys.argv[3:]
    while a:
        if a[0] == '--set': sets.append(tuple(a[1].split('=', 1))); a = a[2:]
        elif a[0] == '--del': dels.append(a[1]); a = a[2:]
        else: raise SystemExit('bad arg ' + a[0])
    t = load(d); apply_edits(t, sets, dels)
    open(out, 'wb').write(build(t))
    print(f'{out}: {os.path.getsize(out)} bytes, {len(t)} nodes')
