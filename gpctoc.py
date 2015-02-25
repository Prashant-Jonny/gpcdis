#!/usr/bin/env python

import sys
from gpclib.decode import GPCDecoder

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print 'usage: {0} file.gbc'.format(sys.argv[0])
        sys.exit(-1)

    # read the entire input
    data = open(sys.argv[1], 'rb').read()

    decoder = GPCDecoder(data)
    
    # decode the entire input
    try:
        decoder.full_decode()
        decoder.combo_decode()
        decoder.init_decode()
    except ValueError as e:
        print e

    lines = []

    # decompile the data segment if there is one
    if decoder.start:
        lines.append('// data segment')
        lines.extend(decoder.start.decompile())
        lines.append('')

    # decompile any remaps
    if decoder.maps:
        lines.append('// mapping segment')
        lines.extend(decoder.maps.decompile(decoder))
        lines.append('')

    # decompile any allocations
    if decoder.allocs:
        lines.append('// variable segment')
        for index,count in sorted(decoder.allocs.items(), key=lambda a: a[0]):
            if index < decoder.combo_count * 3: continue
            if count > 1:
                lines.append('int v{0}[{1}];'.format(index, count))
            else:
                if decoder.alloc_values.has_key(index):
                    lines.append('int {0};'.format(decoder.alloc_values[index]))
                else:
                    lines.append('int v{0};'.format(index))
        lines.append('')

    if decoder.t0:
        lines.append('// titan only instruction to prevent operation on cronus')
        lines.append('{0};'.format(decoder.t0.final_sink.decompile(decoder)));
        lines.append('')

    lines.append('// main segment')

    # decompile init and main
    for sub in sorted(decoder.subs.values(), key=lambda s: s.address):
        if sub.name not in ('init', 'main'): continue
        lines.append('{0} {{'.format(sub.generate_prototype()))
        for line in sub.decompile():
            lines.append('\t{0}'.format(line))
        lines.append('}')
        lines.append('')

    # decompile combos
    if decoder.combos:
        lines.append('// combo segment')
        for idx,combo in enumerate(decoder.combos):
            lines.append('combo combo{0} {{'.format(idx))
            for line in combo.decompile(decoder):
                lines.append('\t{0}'.format(line))
            lines.append('}')
            lines.append('')

    header = False
    # decompile the rest of the subs
    for sub in sorted(decoder.subs.values(), key=lambda s: s.address):
        if sub.name in ('init', 'main'): continue
        if not header:
            lines.append('// function segment')
            header = True
        lines.append('{0} {{'.format(sub.generate_prototype()))
        for line in sub.decompile():
            lines.append('\t{0}'.format(line))
        lines.append('}')
        lines.append('')

    # print all the lines
    for line in lines:
        print line
