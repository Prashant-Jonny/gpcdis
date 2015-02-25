from gpclib.opcodes import opcodes, missing, DataOpCode, FailedOpCode

class GPCStackSource(object):
    _fake = False

    def __init__(self, address, operation):
        self.address = address
        self.operation = operation

    def decompile(self, decoder):
        if self._fake:
            return self._fake
        return self.operation.decompile(decoder)

class GPCStackSink(object):
    def __init__(self, address, operation, sources):
        self.address = address
        self.operation = operation
        self.sources = sources

    def all_sources(self):
        sources = []
        for source in self.sources.values():
            if isinstance(source, GPCStackSink):
                sources.extend(source.all_sources())
            else:
                sources.append(source)
        return sources

    def decompile(self, decoder):
        sorted_ops = sorted(self.sources.items(), key=lambda i: i[0])
        ret_constants = [s.operation._ret_constants for s in self.sources.values() if s.operation._ret_constants]
        sources = [s[1].decompile(decoder) for s in sorted_ops]
        if ret_constants:
            for fix,up in ret_constants[0].items():
                for i, s in enumerate(sources):
                    if s == fix:
                        sources[i] = up
        return self.operation.decompile(decoder, *sources)

class GPCStackSinkSource(GPCStackSink):
    def decompile(self, decoder):
        sorted_ops = sorted(self.sources.items(), key=lambda i: i[0])
        ret_constants = [s.operation._ret_constants for s in self.sources.values() if s.operation._ret_constants]
        sources = []
        for addr, source in sorted_ops:
            if not self.operation._bounded and hasattr(source, 'sources') and not source.operation._bounded:
                sources.append('({0})'.format(source.decompile(decoder)))
            else:
                sources.append(source.decompile(decoder))
        if ret_constants:
            for fix,up in ret_constants[0].items():
                for i, s in enumerate(sources):
                    if s == fix:
                        sources[i] = up
        return self.operation.decompile(decoder, *sources)

class GPCFakeStackSink(object):
    def __init__(self, code):
        self.code = code

    def all_sources(self):
        return []

    def decompile(self, decoder):
        return self.code

class GPCFunctionalGroup(object):
    _jump = False
    _jumpz = False
    _jumped = False
    _jumpzed = False
    _opens_block = False
    _closes_block = False
    next = None
    complex = False

    def __init__(self, address, operations):
        self.address = address
        self.operations = operations

    def all_sinks(self):
        sinks = []
        sinks.append(self.final_sink)
        for source in self.final_sink.all_sources():
            if not isinstance(source, GPCStackSource):
                sinks.append(source)
        return sinks

    def simple(self):
        sorted_ops = sorted(self.operations.items(), key=lambda i: i[0], reverse=True)
        if self.complex:
            return False
        for idx, (addr, op) in enumerate(sorted_ops):
            if not op._simple:
                return False
        return True

    def resolve(self):
        stack = []
        self.final_sink = None
        sink = None
        sorted_ops = sorted(self.operations.items(), key=lambda i: i[0], reverse=True)
        for idx, (addr, op) in enumerate(sorted_ops):
            # if this is the first iteration, store the final sink
            if not self.final_sink:
                self.final_sink = sink = GPCStackSink(addr, op, {})
                if op._jump and op._conditional:
                    self._jumpz = op.jump_address
                elif op._jump:
                    self._jump = op.jump_address
                continue
            
            # if this instruction is a source, append it
            if op._pushes and not op._pops:
                sink.sources[addr] = GPCStackSource(addr, op)
            # if this instruction is a sink and source, put it on the stack and append it
            elif op._pops and op._pushes:
                s = GPCStackSinkSource(addr, op, {})
                sink.sources[addr] = s
                stack.append(sink)
                sink = s
            elif op._pops:
                raise ValueError('cannot have a sink only instruction in the middle of a functional group')
            
            # if the sink is full, pop it from the stack
            if len(sink.sources) > sink.operation._pops:
                raise ValueError('too many sources: {0} {1}'.format(len(sink.sources), sink.operation._pops))
            while len(sink.sources) == sink.operation._pops and len(stack):
                sink = stack.pop()
        return self.final_sink


class GPCLoc(object):
    def __init__(self, address, operations):
        self.address = address
        self.operations = operations
        self.groups = {}

    def split_functional_groups(self):
        stack_depth = 0
        self.groups = {}
        group = None
        sorted_ops = sorted(self.operations.items(), key=lambda i: i[0])
        for idx, (addr, op) in enumerate(sorted_ops):
            # start a new functional group if we hit the stack bottom
            if stack_depth == 0:
                if group:
                    self.groups[group.address] = group
                group = GPCFunctionalGroup(addr, {})

            # check stack depth
            if op._pops > stack_depth:
                raise ValueError('DecodeError at {0.address:0>4X}: tried to pop {0._pops} off stack of {1}'.format(op, stack_depth))

            # add the current op to the group
            group.operations[addr] = op

            # do the stack math
            stack_depth += op._pushes - op._pops
        if group:
            self.groups[group.address] = group
        for group in self.groups.values():
            sorted_ops = sorted(group.operations.items(), key=lambda i: i[0], reverse=True)
            for idx, (addr, op) in enumerate(sorted_ops):
                # we cannot make a single operation group smaller
                if len(group.operations) == 1: break
            
                # last operation does not rely on previous operation
                # probably a jump
                if not op._pushes and not op._pops:
                    group.operations.pop(addr)
                    g = GPCFunctionalGroup(addr, {addr: op})
                    self.groups[g.address] = g
                # last item in functional group cannot push
                # probably a function call with an ingored return
                elif op._pushes:
                    group.operations.pop(addr)
                    g = GPCFunctionalGroup(addr, {addr: op})
                    self.groups[g.address] = g
                # normal ending
                else: break
        for group in self.groups.values():
            group.resolve()
        return self.groups


class GPCBlock(object):
    _condition = False
    _while = False
    _else_pending = False
    _else = False
    _closing = False

    def __init__(self, address, end, groups):
        self.address = address
        self.end = end
        self.groups = groups
        # hack to handle empty blocks
        if address == end:
            self.address -= 0.5

    def all_groups(self):
        groups = {}
        for group in self.groups.values():
            if isinstance(group, GPCBlock):
                groups.update(group.all_groups())
            else:
                groups[group.address] = group
        return groups

    def decompile(self, decoder, level = 0):
        lines = []
        for group in sorted(self.groups.values(), key=lambda g: g.address):
            if isinstance(group, GPCBlock):
                if group._else:
                    lines.append('{0}}} else {{'.format('\t' * level))
                lines.extend(group.decompile(decoder, level + 1))
                if not group._closing:
                    lines.append('{0}}}'.format('\t' * level))
            else:
                endl = ';'
                startl = ''
                if group._closes_block:
                    startl = '} '
                if group._opens_block:
                    endl = ' {'
                code = group.final_sink.decompile(decoder)
                if code:
                    lines.append('{0}{1}{2}{3}'.format('\t' * level, startl, code, endl))
        return lines

class GPCSub(object):
    _pops = 0
    _pushes = 0

    def __init__(self, decoder, name, address, operations):
        self.decoder = decoder
        self.name = name
        self.address = address
        self.operations = operations
        self.locs = {}
        self.groups = {}

    def generate_prototype(self):
        if self.name == 'start': return 'start'
        if self.name == 'init': return 'init'
        if self.name == 'main': return 'main'
        args = []
        for i in range(self._pops):
            args.append('a{0}'.format(i))
        return 'function {0}({1})'.format(self.name, ', '.join(args))

    def split_locs(self):
        self.locs = {}
        self.groups = {}
        loc = None
        sorted_ops = sorted(self.operations.items(), key=lambda i: i[0])
        for idx, (addr, op) in enumerate(sorted_ops):
            if op._sub or op._loc:
                if loc:
                    self.locs[loc.address] = loc
                loc = GPCLoc(op.address, {})
            loc.operations[op.address] = op
        if loc:
            self.locs[loc.address] = loc
        for loc in self.locs.values():
            loc.split_functional_groups()
            self.groups.update(loc.groups)
        last = None
        for group in sorted(self.groups.values(), key=lambda g: g.address):
            if group._jump and group.address != 0:
                self.groups[group._jump]._jumped = group.address
            if group._jumpz:
                self.groups[group._jumpz]._jumpzed = group.address
            if last:
                last.next = group
            last = group
        return sorted(self.locs.values(), key=lambda s: s.address)

    def resolve(self):
        sorted_groups = sorted(self.groups.values(), key=lambda g: g.address)
        self.root = None
        block = None
        stack = []
        for group in sorted_groups:
            # store the root group
            if not self.root:
                self.root = block = GPCBlock(group.address, -1, {})

            # pop the next block off the stack if we are at the end
            while block.end == group.address and len(stack):
                block = stack.pop()

            # this group is super fucking boring
            if not (group._jump or group._jumpz) and not (group._jumped or group._jumpzed):
                block.groups[group.address] = group
                group.block = block
            # this group is a while loop condition
            elif group._jumped and group._jumpz and group._jumped > group.address:
                group.final_sink.operation._fmt_decompile = 'while ({1})'
                group._opens_block = True

                # put the current block on the stack
                stack.append(block)
                
                # put the block opener in the current block
                block.groups[group.address] = group
                group.block = block
                
                # create the nested block
                b = GPCBlock(group.next.address, group._jumpz, {})
                b._condition = group
                b._while = True
                block.groups[b.address] = b
                block = b
            # this group is the while loop end
            elif block._condition and group._jump == block._condition.address:
                block.groups[group.address] = group
                group.block = block
                block = stack.pop()
            elif block._condition and group._jump:
                parents = [p for p in stack if p._while and p._condition._jumpz == group._jump]
                # this group is a break statement within a while loop
                if parents:
                    group.final_sink.operation._fmt_decompile = 'break'
                    block.groups[group.address] = group
                    group.block = block
                # this group is the end of an if block which has else (if) following
                else:
                    block.groups[group.address] = group
                    group.block = block
                    block._closing = True
                    cond = block._condition
                    block = stack.pop()
                    block._else_pending = group._jump
                    block._else_condition = cond
            # this group is an else block
            elif group._jumpzed and not (group._jump or group._jumpz) and block._else_pending:
                # put the current block on the stack
                stack.append(block)
                
                # create the nested block
                b = GPCBlock(group.address, block._else_pending, {group.address: group})
                block._else_pending = False
                b._else = True
                b._condition = block._else_condition
                block.groups[b.address] = b
                block = b
            # this group comes after a conditional block
            elif (group._jumped or group._jumpzed) and not (group._jump or group._jumpz):
                block.groups[group.address] = group
                group.block = block
            elif group._jumpzed and group._jumpz and block._else_pending:
                next = self.groups[group._jumpz]
                found = False
                while next.address < block._else_pending:
                    if not next._jumpz:
                        found = True
                        break
                    next = self.groups[next._jumpz]
                # this group is an if condition at the start of an else block
                if found:
                    group._opens_block = True
                    
                    # put the current block on the stack
                    stack.append(block)
                    
                    # create the else block and put it on the stack
                    b = GPCBlock(group.address, block._else_pending, {})
                    block._else_pending = False
                    b._else = True
                    b._condition = block._else_condition
                    block.groups[b.address] = b
                    block = b
                    stack.append(block)
                    
                    # put the block opener in the current block
                    block.groups[group.address] = group
                    group.block = block
                    
                    # create the nested block
                    b = GPCBlock(group.next.address, group._jumpz, {})
                    b._condition = group
                    block.groups[b.address] = b
                    block = b
                # this group is an else if condition
                else:
                    block._else_pending = False
                    group.final_sink.operation._fmt_decompile = 'else if ({1})'
                    group._opens_block = True
                    group._closes_block = True

                    # put the current block on the stack
                    stack.append(block)
                    
                    # put the block opener in the current block
                    block.groups[group.address] = group
                    group.block = block
                    
                    # create the nested block
                    b = GPCBlock(group.next.address, group._jumpz, {})
                    b._condition = group
                    block.groups[b.address] = b
                    block = b
            # this group is an if condition
            elif group._jumpz:
                group._opens_block = True
                
                # put the current block on the stack
                stack.append(block)
                
                # put the block opener in the current block
                block.groups[group.address] = group
                group.block = block
                
                # create the nested block
                b = GPCBlock(group.next.address, group._jumpz, {})
                b._condition = group
                block.groups[b.address] = b
                block = b

    def decompile(self):
        return self.root.decompile(self.decoder)

class GPCDecoder(object):
    def __init__(self, data):
        self.data = data
        self.operations = {}
        self.subs = {}
        self.start = None
        self.init = None
        self.main = None
        self.maps = None
        self.combos = None
        self.combo_count = 0
        self.t0 = None
        self.variables = {}

    def full_decode(self):
        self.decode(0)
        self.fill_gaps()
        self.generate_labels()
        self.split_subs()
        self.resolve_allocs()
        self.normalize_init()
        self.resolve()
        self.resolve_variables()

    def combo_decode(self):
        self.split_combos()
        self.resolve_combos()
        self.fix_run_combo()

    def init_decode(self):
        self.renormalize_init()

    def decode(self, address):
        if address in self.operations:
            return
        opcode = ord(self.data[address])
        if opcode in missing:
            o = FailedOpCode(self.data, address, missing[opcode])
            self.operations[address] = o
            return self.decode(address + o.size)
        for op in opcodes:
            if op._op != opcode:
                continue
            o = op()
            l = o.parse(self.data, address)
            self.operations[address] = o
            address += l
            break
        else:
            raise ValueError('Decode Error at {0:0>4X}: {1:X}'.format(address, opcode))
        if o._jump and o._conditional:
            self.decode(o.jump_address)
        elif o._jump:
            address = o.jump_address
        if address < len(self.data):
            self.decode(address)

    def fill_gaps(self):
        sorted_ops = sorted(self.operations.items(), key=lambda i: i[0])
        for idx, (addr, op) in enumerate(sorted_ops):
            if idx + 1 < len(sorted_ops):
                end = addr + op.size
                next = sorted_ops[idx+1][0]
                if end < next:
                    size = next - end
                    self.operations[end] = DataOpCode(self.data, end, size)

    def generate_labels(self):
        self.operations[0]._sub = 'start'
        if self.operations[0]._name == 'jmp':
            self.operations[0]._sub = 'start'
            self.operations[self.operations[0].jump_address]._sub = 'init'
        else:
            self.operations[0]._sub = 'init'
        sorted_ops = sorted(self.operations.items(), key=lambda i: i[0])
        for idx, (addr, op) in enumerate(sorted_ops):
            if op._name == 'main':
                self.operations[addr]._sub = 'main'
            elif op._call:
                self.operations[op.jump_address]._sub = 'sub_{0:0>4X}'.format(op.jump_address)
            elif op._jump and op.address != 0:
                self.operations[op.jump_address]._loc = 'loc_{0:0>4X}'.format(op.jump_address)

    def split_subs(self):
        self.subs = {}
        sub = None
        sorted_ops = sorted(self.operations.items(), key=lambda i: i[0])
        for idx, (addr, op) in enumerate(sorted_ops):
            if op._sub:
                if sub and sub.name != 'start':
                    self.subs[sub.address] = sub
                sub = GPCSub(self, op._sub, op.address, {})
                if sub.name == 'start':
                        self.start = sub
                elif sub.name == 'init':
                    self.init = sub
                elif sub.name == 'main':
                    self.main = sub
            sub.operations[op.address] = op
        if sub:
            self.subs[sub.address] = sub
        for idx, (addr, op) in enumerate(sorted_ops):
            if op._call:
                sub = self.subs[op.jump_address]
                sub._pops = op.arguments[1]
                sub._pushes = op.arguments[2]
        if self.start:
            self.start.split_locs()
            self.start.resolve()
        if self.init:
            self.init.split_locs()
            self.init.resolve()

    def resolve_allocs(self):
        total = 0
        self.allocs = {}
        self.vars = {}
        if not self.init: return
        for op in sorted(self.init.operations.values(), key=lambda o: o.address):
            if op._name == 'alloc':
                count = op.arguments[0]
                if count > 1:
                    for i in range(count):
                        self.vars[total + i] = 'v{0}[{1}]'.format(total, i)
                else:
                    self.vars[total] = 'v{0}'.format(total)
                self.allocs[total] = count
                total += count
        if self.allocs[0] % 3 == 0:
            self.combo_count = self.allocs[0] / 3

    def normalize_init(self):
        if not self.init: return
        self.maps = GPCBlock(0, -1, {})
        for group in sorted(self.init.groups.values(), key=lambda g: g.address):
            if group.final_sink.operation._name == 'alloc':
                self.init.groups.pop(group.address)
            if group.final_sink.operation._name in ('remap', 'unmap'):
                self.init.groups.pop(group.address)
                self.maps.groups[group.address] = group
        if not self.maps.groups:
            self.maps = None
        if not self.init.operations:
            self.subs.pop(self.init.address)
            self.init = None

    def renormalize_init(self):
        if not self.init: return
        self.alloc_values = {}
        for group in sorted(self.init.groups.values(), key=lambda g: g.address):
            if not hasattr(group.final_sink, 'operation'): continue
            if not group.simple(): break
            if group.final_sink.operation._name == 'pop':
                var = group.final_sink.operation.arguments[0]
                self.alloc_values[var] = group.final_sink.decompile(self)
                self.init.groups.pop(group.address)
            if group.final_sink.operation._name == 'T0':
                self.t0 = group
                self.init.groups.pop(group.address)
        self.init.resolve()

    def resolve(self):
        for sub in self.subs.values():
            if sub.name != 'init':
                sub.split_locs()
                sub.resolve()

    def resolve_variables(self):
        variables = {}
        groups = {}
        for sub in self.subs.values():
            groups.update(sub.groups)
        sinks = {}
        for group in groups.values():
            for sink in group.all_sinks():
                sinks[sink] = sink.sources.values()
        for sink, sources in sinks.items():
            if not sink.operation._constants: continue
            sources = sorted(sources, key=lambda s: s.address)
            for sidx,source in enumerate(sources):
                snkidx = sidx - len(sink.operation.arguments or [])
                if snkidx >= len(sink.operation._constants) or not sink.operation._constants[snkidx]: continue
                if not source.operation._variables: continue
                if sidx >= len(source.operation._variables) or not source.operation._variables[sidx]: continue
                arg = source.operation.arguments[0]
                variables[arg] = sink.operation._constants[snkidx]
        for sink, sources in sinks.items():
            if not sink.operation._variables: continue
            arg = sink.operation.arguments[0]
            if variables.has_key(arg):
                sink.operation._constants = (False, variables[arg],)

    def split_combos(self):
        if not self.combo_count: return
        self.combos = []
        groups = sorted(self.main.root.groups.values(), key=lambda g: g.address)[self.combo_count * -2 - 1:]
        combos = [(groups[i], groups[i+1]) for i in range(0, len(groups) - 1, 2)]
        for case,block in combos:
            self.main.root.groups.pop(case.address)
            self.main.root.groups.pop(block.address)
            self.combos.append(GPCBlock(0, -1, {case.address: case, block.address: block}))
        if not self.combos:
            self.combos = None

    def resolve_combos(self):
        if not self.combos: return
        for idx, super_block in enumerate(self.combos):
            outer_block = sorted(super_block.groups.values(), key=lambda g: g.address)[-1]
            inner_blocks = [b for b in sorted(outer_block.groups.values(), key=lambda g: g.address) if isinstance(b, GPCBlock)][2:]
            self.combos[idx] = GPCBlock(0, -1, {})
            groups = {}
            for block in inner_blocks:
                g = self.flatten_combo(idx, block)
                groups.update(g)
            for group in groups.values():
                self.fix_combo_calls(group)
                self.combos[idx].groups[group.address] = group
            self.fix_combos(self.combos[idx])

    def flatten_combo(self, idx, block):
        groups = {}
        expected = []
        for i in range(3):
            expected.append('v0[{0}]'.format(idx * 3 + i))
        if isinstance(block, GPCBlock):
            actual = sorted([s.decompile(self) for s in block._condition.final_sink.all_sources()])
            if len(actual) == 2 and expected[2] == actual[1]:
                for group in block.groups.values():
                    groups.update(self.flatten_combo(idx, group))
            else:
                groups[block.address] = block
        else:
            actual = sorted([s.decompile(self) for s in block.final_sink.all_sources()])
            if block.final_sink.operation._name == 'pop' and 'v0[{0}]'.format(block.final_sink.operation.arguments[0]) in expected and actual[0] == '0':
                pass
            elif len(actual) == 2 and expected[2] == actual[1]:
                pass
            else:
                groups[block.address] = block
        return groups

    def fix_combo_calls(self, group):
        if isinstance(group, GPCBlock):
            for grp in group.groups.values():
                self.fix_combo_calls(grp)
        else:
            valid = False
            try:
                op = group.final_sink.operation
                srcop = group.final_sink.sources.values()[0].operation
                valid = op._name == 'pop' and op.arguments[0] % 3 == 0 and srcop._name == 'pushi' and srcop.arguments[0] == 1
            except: pass
            if valid:
                combo_index = op.arguments[0] / 3
                group.final_sink = GPCFakeStackSink('call(combo{0})'.format(combo_index))
            valid = False
            try:
                op = group.final_sink.operation
                srcop = group.final_sink.sources.values()[0].operation
                valid = op._name == 'pop' and (op.arguments[0] - 1) % 3 == 0 and srcop._name == 'mul'
            except: pass
            if valid:
                group.final_sink = GPCFakeStackSink('')

    def fix_combos(self, block):
        for group in sorted(block.groups.values(), key=lambda g: g.address):
            if isinstance(group, GPCBlock):
                self.fix_combos(group)
            else:
                op1valid = False
                op2valid = False
                op3valid = False
                try:
                    op1 = group.final_sink.operation
                    srcop1 = group.final_sink.sources.values()[0].operation
                    op1valid = op1._name == 'pop' and op1.arguments[0] % 3 == 0 and op1.arguments[0] < (self.combo_count * 3) and srcop1._name == 'pushi'
                    op2 = group.next.final_sink.operation
                    srcop2 = group.next.final_sink.sources.values()[0].operation
                    op2valid = op2._name == 'pop' and (op2.arguments[0] - 1) % 3 == 0 and op2.arguments[0] < (self.combo_count * 3) and srcop2._name == 'pushi' and srcop2.arguments[0] == 0
                    op3 = group.next.next.final_sink.operation
                    srcop3 = group.next.next.final_sink.sources.values()[0].operation
                    op3valid = op3._name == 'pop' and (op3.arguments[0] - 2) % 3 == 0 and op3.arguments[0] < (self.combo_count * 3) and srcop3._name == 'pushi' and srcop3.arguments[0] == 0
                except: pass
                if op1valid:
                    combo_index = op1.arguments[0] / 3
                    if op1valid and op2valid and op3valid:
                        if srcop1.arguments[0] == 1:
                            group.final_sink = GPCFakeStackSink('combo_restart(combo{0})'.format(combo_index))
                        else:
                            group.final_sink = GPCFakeStackSink('combo_stop(combo{0})'.format(combo_index))
                        group.complex = True
                        group.next.final_sink = GPCFakeStackSink('')
                        group.next.complex = True
                        group.next.next.final_sink = GPCFakeStackSink('')
                        group.next.next.complex = True
                    elif op1valid:
                        group.final_sink = GPCFakeStackSink('combo_run(combo{0})'.format(combo_index))
                for source in group.final_sink.all_sources():
                    valid = False
                    try:
                        op = source.operation
                        valid = op._name == 'push' and op.arguments[0] % 3 == 0 and op.arguments[0] < (self.combo_count * 3)
                    except: pass
                    if not valid: continue
                    combo_index = op.arguments[0] / 3
                    source._fake = 'combo_running(combo{0})'.format(combo_index)

    def fix_run_combo(self):
        for sub in self.subs.values():
            self.fix_combos(sub.root)


