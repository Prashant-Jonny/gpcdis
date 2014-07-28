#!/usr/bin/env python

import sys
from gpclib.decode import GPCDecoder


def print_sink(sink, i = 0):
    sorted_sources = sorted(sink.sources.items(), key=lambda i: i[0])
    for idx, (addr, source) in enumerate(sorted_sources):
        if hasattr(source, 'sources'):
            print_sink(source, i + 1)
        else:
            print '{0:0>4X}\t\t\t{1}{2}'.format(source.address, '\t'*i, source.operation)
    print '{0:0>4X}\t\t{1}{2}'.format(sink.address, '\t'*i, sink.operation)

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
    except ValueError as e:
        print e

    subs = decoder.subs.values()
    if decoder.init:
        subs.insert(0, decoder.init)
    if decoder.start:
        subs.insert(0, decoder.start)

    # print all the subs
    for sub in sorted(subs, key=lambda s: s.address):
        print '{0:0>4X} {1}:'.format(sub.address, sub.generate_prototype())
        for group in sorted(sub.groups.values(), key=lambda g: g.address):
            jumped_from = ''
            jump_to = ''
            a = group._jump or group._jumpz or -1
            if a > 0:
                jump_to = ' {1}> g_{0:0>4X}'.format(a, '-' if group._jump else '?')
            a = group._jumped or group._jumpzed or -1
            if a > 0:
                jumped_from = 'g_{0:0>4X} {1}> '.format(a, '-' if group._jumped else '?')
            print '{0:0>4X} \t{2}(g_{0:0>4X}){1}'.format(group.address, jump_to, jumped_from)
            sink = group.resolve()
            print_sink(sink)
