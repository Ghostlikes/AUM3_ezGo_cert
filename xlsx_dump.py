#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""xlsx_dump.py - 鍙瀵煎嚭 xlsx 鐨勫崟鍏冩牸鏂囨湰锛坰tdin 鏃犲叧锛岀函鏍囧噯搴擄級
鐢ㄦ硶: python3 xlsx_dump.py <book.xlsx> --list
      python3 xlsx_dump.py <book.xlsx> --sheet AUM-3 [--rows 130-160] [--tsv]
"""
import sys, re, zipfile
import xml.etree.ElementTree as ET

NS = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'
RNS = '{http://schemas.openxmlformats.org/officeDocument/2006/relationships}'


def load(path):
    z = zipfile.ZipFile(path)
    shared = []
    if 'xl/sharedStrings.xml' in z.namelist():
        root = ET.fromstring(z.read('xl/sharedStrings.xml'))
        for si in root.findall(NS + 'si'):
            shared.append(''.join(t.text or '' for t in si.iter(NS + 't')))
    wb = ET.fromstring(z.read('xl/workbook.xml'))
    rels = ET.fromstring(z.read('xl/_rels/workbook.xml.rels'))
    rel = {r.get('Id'): r.get('Target') for r in rels}
    sheets = []
    for sh in wb.iter(NS + 'sheet'):
        target = rel.get(sh.get(RNS + 'id'), '')
        if not target.startswith('xl/'):
            target = 'xl/' + target.lstrip('/')
        sheets.append((sh.get('name'), target))
    return z, shared, sheets


def colnum(ref):
    m = re.match(r'([A-Z]+)(\d+)', ref)
    if not m:
        return 0, 0
    col = 0
    for ch in m.group(1):
        col = col * 26 + (ord(ch) - 64)
    return col, int(m.group(2))


def dump(path, sheet, rows=None, tsv=False):
    z, shared, sheets = load(path)
    target = dict(sheets).get(sheet)
    if target is None:
        print('sheet 涓嶅瓨鍦? %s' % sheet, file=sys.stderr)
        return 2
    root = ET.fromstring(z.read(target))
    out = {}
    maxcol = 0
    for c in root.iter(NS + 'c'):
        ref = c.get('r') or ''
        col, row = colnum(ref)
        if rows and not (rows[0] <= row <= rows[1]):
            continue
        t = c.get('t')
        v = c.find(NS + 'v')
        isnode = c.find(NS + 'is')
        if t == 's' and v is not None:
            txt = shared[int(v.text)] if v.text and int(v.text) < len(shared) else ''
        elif t == 'inlineStr' and isnode is not None:
            txt = ''.join(x.text or '' for x in isnode.iter(NS + 't'))
        elif v is not None:
            txt = v.text or ''
        else:
            txt = ''
        txt = re.sub(r'\s+', ' ', txt).strip()
        if txt:
            out.setdefault(row, {})[col] = txt
            maxcol = max(maxcol, col)
    for row in sorted(out):
        cells = out[row]
        if tsv:
            print('\t'.join(cells.get(c, '') for c in range(1, maxcol + 1)))
        else:
            parts = ['%s%d=%s' % (chr(64 + c) if c <= 26 else 'C%d' % c, row, cells[c]) for c in sorted(cells)]
            print('R%d  %s' % (row, ' | '.join(parts)))
    return 0


if __name__ == '__main__':
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(2)
    book = args[0]
    if '--list' in args:
        _z, _s, sheets = load(book)
        for name, _ in sheets:
            print(name)
        sys.exit(0)
    sheet = args[args.index('--sheet') + 1] if '--sheet' in args else None
    rows = None
    if '--rows' in args:
        a, b = args[args.index('--rows') + 1].split('-')
        rows = (int(a), int(b))
    sys.exit(dump(book, sheet, rows, '--tsv' in args))
