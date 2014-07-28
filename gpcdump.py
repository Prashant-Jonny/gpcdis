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
    except ValueError as e:
        print e

    # print all the opcodes
    sorted_ops = sorted(decoder.operations.items(), key=lambda i: i[0])
    for idx, (addr, op) in enumerate(sorted_ops):
        if op._sub:
            print '{0:0>4X} {1}:'.format(addr, op._sub)
        if op._loc:
            print '{0:0>4X} \t{1}:'.format(addr, op._loc)
        print '{0:0>4X}\t\t{1}'.format(addr, op)
