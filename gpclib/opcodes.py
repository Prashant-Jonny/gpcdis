import struct
from gpclib.constants import *

class OpCode(object):
    _op = -1
    _name = None
    _arguments = None
    _variables = None
    _arguments_fmt = None
    _constants = None
    _ret_constants = None
    _fmt_decompile = None
    _jump = False
    _call = False
    _conditional = False
    _loc = False
    _sub = False
    _bounded = False
    _pops = 0
    _pushes = 0
    address = 0
    size = 0

    def __init__(self):
        self.arguments = None
        self.stack = None
    
    def parse(self, data, address):
        self.size = 0
    
        # check for the correct op code
        if data[address] != chr(self._op):
            return self.size
        
        # store the address
        self.address = address
        self.size = 1
        
        # check for arguments
        if self._arguments is None:
            return self.size
        
        # unpack the arguments
        args = '<' + ''.join(self._arguments)
        self.arguments = struct.unpack_from(args, data, address + 1)
        self.size += struct.calcsize(args)
        
        # store any jump or call
        if self._jump or self._call:
            self.jump_address = self.arguments[self._target]
        
        return self.size
    
    def _fmt_args(self):
        if self.arguments is None:
            return ''
        if self._arguments_fmt is None:
            raise NotImplementedError()
        return self._arguments_fmt.format(*self.arguments)
    
    def __repr__(self):
        if self._name is None:
            raise NotImplementedError()
        args = self._fmt_args()
        return '{0}\t{1}'.format(self._name, args)

    def decompile(self, decoder, *args):
        if self._fmt_decompile is None:
            return '// {0}'.format(self)
        a = []
        if self.arguments:
            a.extend(self.arguments)
        a.extend(args)
        if self._constants:
            for idx, const in enumerate(self._constants):
                if const:
                    if a[idx] in const:
                        a[idx] = const[a[idx]]
        if self._variables:
            for idx, is_var in enumerate(self._variables):
                if is_var:
                    a[idx] = decoder.vars[a[idx]]
        return self._fmt_decompile.format(*a, d=decoder)

class FailedOpCode(OpCode):
    _name = 'OP_'
    def __init__(self, data, address, length):
        super(FailedOpCode, self).__init__()
        self.address = address
        self.size = length
        self._op = ord(data[address])
        self._name += '{0:0>2X}'.format(self._op)
        self.arguments = struct.unpack_from('<' + 'B' * (length - 1), data, address + 1)
        self._arguments_fmt = ''
        for i in range(0, (length - 1)):
            self._arguments_fmt += '{' + '{0}'.format(i) + ':0>2X} '
class DataOpCode(OpCode):
    _name = '.data'
    _bounded = True
    def __init__(self, data, address, length):
        super(DataOpCode, self).__init__()
        self.address = address
        self.size = length
        self.arguments = struct.unpack_from('<' + 'B' * (length ), data, address)
        self._arguments_fmt = ''
        data = []
        for i in range(0, length):
            self._arguments_fmt += '{' + '{0}'.format(i) + ':0>2X} '
            data.append('{{{0}}}'.format(i))
        self._fmt_decompile = 'data({0})'.format(', '.join(data))
class HalfOpCode(OpCode):
    _arguments = ('B')
    _arguments_fmt = '{0:0>2X}'
class TypicalOpCode(OpCode):
    _arguments = ('h')
    _arguments_fmt = '{0:0>4X}'
class MainEndOpCode(OpCode):
    _op = 0x00
    _name = 'end'
    _fmt_decompile = ''
class RemapOpCode(TypicalOpCode):
    _op = 0x02
    _name = 'remap'
    _arguments = ('B', 'B')
    _constants = (BUTTONS, BUTTONS)
    _arguments_fmt = '{0:0>2X} {1:0>2X}'
    _fmt_decompile = 'remap {0} -> {1}'
    _bounded = True
class MainStartOpCode(OpCode):
    _op = 0x01
    _name = 'main'
    _fmt_decompile = ''
class AllocateOpCode(HalfOpCode):
    _op = 0x03
    _name = 'alloc'
    _fmt_decompile = ''
class PushOpCode(TypicalOpCode):
    _op = 0x04
    _name = 'push'
    _arguments_fmt = 'var_{0:0>2X}'
    _pushes = 1
    _fmt_decompile = '{0}'
    _variables = (True,)
class PushImmediateOpCode(TypicalOpCode):
    _op = 0x05
    _name = 'pushi'
    _arguments_fmt = '0x{0:X}'
    _pushes = 1
    _fmt_decompile = '{0}'
class PopOpCode(TypicalOpCode):
    _op = 0x06
    _name = 'pop'
    _arguments_fmt = 'var_{0:0>2X}'
    _pops = 1
    _fmt_decompile = '{0} = {1}'
    _variables = (True,)
    _bounded = True
class WaitOpCode(TypicalOpCode):
    _op = 0x07
    _name = 'wait'
    _pops = 1
    _fmt_decompile = 'wait({1})'
    _bounded = True
class JumpOpCode(TypicalOpCode):
    _op = 0x08
    _name = 'jmp'
    _jump = True
    _target = 0
    _arguments_fmt = 'loc_{0:0>4X}'
    _fmt_decompile = ''
class JumpZeroOpCode(TypicalOpCode):
    _op = 0x09
    _name = 'jmpz'
    _jump = True
    _conditional = True
    _target = 0
    _arguments_fmt = 'loc_{0:0>4X}'
    _pops = 1
    _fmt_decompile = 'if ({1})'
    _constants = (False, TRUTHS)
class AndOpCode(OpCode):
    _op = 0x0A
    _name = 'and'
    _pops = 2
    _pushes = 1
    _fmt_decompile = '{0} && {1}'
class OrOpCode(OpCode):
    _op = 0x0B
    _name = 'or'
    _pops = 2
    _pushes = 1
    _fmt_decompile = '{0} || {1}'
class EqualOpCode(OpCode):
    _op = 0x0C
    _name = 'eq'
    _pops = 2
    _pushes = 1
    _fmt_decompile = '{0} == {1}'
class NotEqualOpCode(OpCode):
    _op = 0x0D
    _name = 'neq'
    _pops = 2
    _pushes = 1
    _fmt_decompile = '{0} != {1}'
class LessThanOpCode(OpCode):
    _op = 0x0E
    _name = 'lt'
    _pops = 2
    _pushes = 1
    _fmt_decompile = '{0} < {1}'
class LessThanEqualOpCode(OpCode):
    _op = 0x0F
    _name = 'lte'
    _pops = 2
    _pushes = 1
    _fmt_decompile = '{0} <= {1}'
class GreaterThanOpCode(OpCode):
    _op = 0x10
    _name = 'gt'
    _pops = 2
    _pushes = 1
    _fmt_decompile = '{0} > {1}'
class GreaterThanEqualOpCode(OpCode):
    _op = 0x11
    _name = 'gte'
    _pops = 2
    _pushes = 1
    _fmt_decompile = '{0} >= {1}'
class AddOpCode(OpCode):
    _op = 0x12
    _name = 'add'
    _pops = 2
    _pushes = 1
    _fmt_decompile = '{0} + {1}'
class SubtractOpCode(OpCode):
    _op = 0x13
    _name = 'sub'
    _pops = 2
    _pushes = 1
    _fmt_decompile = '{0} - {1}'
class MultiplyOpCode(OpCode):
    _op = 0x14
    _name = 'mul'
    _pops = 2
    _pushes = 1
    _fmt_decompile = '{0} * {1}'
class DivideOpCode(OpCode):
    _op = 0x15
    _name = 'div'
    _pops = 2
    _pushes = 1
    _fmt_decompile = '{0} / {1}'
class NotOpCode(OpCode):
    _op = 0x16
    _name = 'not'
    _pops = 1
    _pushes = 1
    _fmt_decompile = '!{0}'
    _constants = (TRUTHS,)
class GetRtimeOpCode(OpCode):
    _op = 0x17
    _name = 'grtime'
    _pushes = 1
    _fmt_decompile = 'get_rtime()'
class SetValOpCode(OpCode):
    _op = 0x18
    _name = 'sval'
    _pops = 2
    _fmt_decompile = 'set_val({0}, {1})'
    _bounded = True
    _constants = (BUTTONS,)
class GetValOpCode(OpCode):
    _op = 0x19
    _name = 'gval'
    _pops = 1
    _pushes = 1
    _fmt_decompile = 'get_val({0})'
    _bounded = True
    _constants = (BUTTONS,)
class GetLvalOpCode(OpCode):
    _op = 0x1A
    _name = 'glval'
    _pops = 1
    _pushes = 1
    _fmt_decompile = 'get_lval({0})'
    _bounded = True
    _constants = (BUTTONS,)
class GetPtimeOpCode(OpCode):
    _op = 0x1B
    _name = 'gptime'
    _pops = 1
    _pushes = 1
    _fmt_decompile = 'get_ptime({0})'
    _bounded = True
    _constants = (BUTTONS,)
class EventPressOpCode(OpCode):
    _op = 0x1C
    _name = 'eventpress'
    _pops = 1
    _pushes = 1
    _fmt_decompile = 'event_press({0})'
    _bounded = True
    _constants = (BUTTONS,)
class EventReleaseOpCode(OpCode):
    _op = 0x1D
    _name = 'eventrelease'
    _pops = 1
    _pushes = 1
    _fmt_decompile = 'event_release({0})'
    _bounded = True
    _constants = (BUTTONS,)
class TurnOffOpCode(OpCode):
    _op = 0x1E
    _name = 'turnoff'
    _fmt_decompile = 'turn_off()'
class SwapOpCode(OpCode):
    _op = 0x1F
    _name = 'swap'
    _pops = 2
    _fmt_decompile = 'swap({0}, {1})'
    _bounded = True
    _constants = (BUTTONS, BUTTONS)
class BlockOpCode(OpCode):
    _op = 0x20
    _name = 'block'
    _pops = 2
    _fmt_decompile = 'block({0}, {1})'
    _bounded = True
    _constants = (BUTTONS,)
class SensitivityOpCode(OpCode):
    _op = 0x21
    _name = 'sens'
    _pops = 3
    _fmt_decompile = 'sensitivity({0}, {1}, {2})'
    _bounded = True
    _constants = (BUTTONS, False, SENS)
class SetLedOpCode(OpCode):
    _op = 0x22
    _name = 'sled'
    _pops = 2
    _fmt_decompile = 'set_led({0}, {1})'
    _bounded = True
    _constants = (LEDS,)
class GetLedOpCode(OpCode):
    _op = 0x23
    _name = 'gled'
    _pops = 1
    _pushes = 1
    _fmt_decompile = 'get_led({0})'
    _bounded = True
    _constants = (LEDS,)
class SetRumbleOpCode(OpCode):
    _op = 0x24
    _name = 'srumble'
    _pops = 2
    _fmt_decompile = 'set_rumble({0}, {1})'
    _bounded = True
    _constants = (RUMBLE,)
class GetRumbleOpCode(OpCode):
    _op = 0x25
    _name = 'grumble'
    _pops = 1
    _pushes = 1
    _fmt_decompile = 'get_rumble({0})'
    _bounded = True
    _constants = (RUMBLE,)
class LoadSlotOpCode(OpCode):
    _op = 0x26
    _name = 'loadslot'
    _pops = 1
    _fmt_decompile = 'load_slot({0})'
    _bounded = True
class AbsOpCode(OpCode):
    _op = 0x27
    _name = 'abs'
    _pops = 1
    _pushes = 1
    _fmt_decompile = 'abs({0})'
    _bounded = True
class ResetLedOpCode(OpCode):
    _op = 0x28
    _name = 'resetleds'
    _fmt_decompile = 'reset_leds()'
class BlockRumbleOpCode(OpCode):
    _op = 0x29
    _name = 'blockrumble'
    _fmt_decompile = 'block_rumble()'
class ResetRumbleOpCode(OpCode):
    _op = 0x2A
    _name = 'resetrumble'
    _fmt_decompile = 'reset_rumble()'
class VmtCtrlOpCode(OpCode):
    _op = 0x2B
    _name = 'vmtctrl'
    _pops = 1
    _fmt_decompile = 'vm_tctrl({0})'
    _bounded = True
class InverseOpCode(OpCode):
    _op = 0x2C
    _name = 'inv'
    _pops = 1
    _pushes = 1
    _fmt_decompile = 'inv({0})'
    _bounded = True
class WiirOffScreenOpCode(OpCode):
    _op = 0x2D
    _name = 'wroscr'
    _pushes = 1
    _fmt_decompile = 'wiir_offscreen()'
class PowOpCode(OpCode):
    _op = 0x2E
    _name = 'pow'
    _pops = 2
    _pushes = 1
    _fmt_decompile = 'pow({0}, {1})'
    _bounded = True
class IntSqrtOpCode(OpCode):
    _op = 0x2F
    _name = 'isqrt'
    _pops = 1
    _pushes = 1
    _fmt_decompile = 'isqrt({0})'
    _bounded = True
class StickizeOpCode(OpCode):
    _op = 0x30
    _name = 'stickize'
    _pops = 3
    _fmt_decompile = 'stickize({0}, {1}, {2})'
    _constants = (BUTTONS, BUTTONS)
    _bounded = True
class UnmapOpCode(HalfOpCode):
    _op = 0x31
    _name = 'unmap'
    _fmt_decompile = 'unmap {0}'
    _constants = (BUTTONS,)
    _bounded = True
class DeadZoneOpCode(OpCode):
    _op = 0x32
    _name = 'dzone'
    _pops = 4
    _fmt_decompile = 'deadzone({0}, {1}, {2}, {3})'
    _constants = (BUTTONS, BUTTONS)
    _bounded = True
class ModulusOpCode(OpCode):
    _op = 0x33
    _name = 'mod'
    _pops = 2
    _pushes = 1
    _fmt_decompile = '{0} % {1}'
class SetPvarOpCode(OpCode):
    _op = 0x34
    _name = 'spvar'
    _pops = 2
    _fmt_decompile = 'set_pvar({0}, {1})'
    _bounded = True
    _constants = (PVARS,)
class GetPvarOpCode(OpCode):
    _op = 0x35
    _name = 'gpvar'
    _pops = 4
    _pushes = 1
    _fmt_decompile = 'get_pvar({0}, {1}, {2}, {3})'
    _bounded = True
    _constants = (PVARS,)
class CallOpCode(OpCode):
    _op = 0x36
    _name = 'call'
    _call = True
    _target = 0
    _arguments = ('h', 'B', 'B')
    _arguments_fmt = 'sub_{0:0>4X} {1:0>2X} {2:0>2X}'
    _fmt_decompile = 'sub_{0:0>4X}('
    _bounded = True
    
    def parse(self, data, address):
        l = super(CallOpCode, self).parse(data, address)
        if l > 0:
            self._pops = self.arguments[1]
            self._pushes = self.arguments[2]
            args = []
            for i in range(self._pops):
                args.append('{{{0}}}'.format(i + 3))
            self._fmt_decompile = self._fmt_decompile + ', '.join(args) + ')'
        return l
class RetOpCode(HalfOpCode):
    _op = 0x37
    _name = 'ret'
    _fmt_decompile = 'return'
    _bounded = True
    def parse(self, data, address):
        l = super(RetOpCode, self).parse(data, address)
        if l > 0:
            self._pops = self.arguments[0]
            if self._pops:
                self._fmt_decompile = 'return {1}'
        return l
class PushArgumentOpCode(TypicalOpCode):
    _op = 0x38
    _name = 'pusha'
    _arguments_fmt = 'a{0}'
    _pushes = 1
    _fmt_decompile = 'a{0}'
class PopArgumentOpCode(TypicalOpCode):
    _op = 0x39
    _name = 'popa'
    _arguments_fmt = 'a{0}'
    _pops = 1
    _fmt_decompile = 'a{0} = {1}'
class SetLedxOpCode(OpCode):
    _op = 0x3A
    _name = 'sledx'
    _pops = 2
    _fmt_decompile = 'set_ledx({0}, {1})'
    _bounded = True
    _constants = (LEDS,)
class GetLedxOpCode(OpCode):
    _op = 0x3B
    _name = 'gledx'
    _pushes = 1
    _fmt_decompile = 'get_ledx()'
class GetConsoleOpCode(OpCode):
    _op = 0x3C
    _name = 'gcnsl'
    _pushes = 1
    _fmt_decompile = 'get_console()'
    _ret_constants = PIO
class GetControllerOpCode(OpCode):
    _op = 0x3D
    _name = 'gctrl'
    _pushes = 1
    _fmt_decompile = 'get_controller()'
    _ret_constants = PIO
class XorOpCode(OpCode):
    _op = 0x3E
    _name = 'xor'
    _pops = 2
    _pushes = 1
    _fmt_decompile = '{0} ^^ {1}'
class PushIndexedOpCode(TypicalOpCode):
    _op = 0x3F
    _name = 'pushidx'
    _pops = 1
    _pushes = 1
    _fmt_decompile = '{0}[{1}]'
    _variables = (True,)
class PopIndexedOpCode(TypicalOpCode):
    _op = 0x40
    _name = 'popidx'
    _pops = 2
    _fmt_decompile = '{0}[{1}] = {2}'
    _variables = (True,)
class GetSlotOpCode(OpCode):
    _op = 0x41
    _name = 'getslot'
    _pushes = 1
    _fmt_decompile = 'get_slot()'
class SetBitOpCode(TypicalOpCode):
    _op = 0x42
    _name = 'sbit'
    _arguments_fmt = 'var_{0:0>2X}'
    _pops = 1
    _variables = (True,)
    _fmt_decompile = 'set_bit({1}, {0})'
class ClearBitOpCode(TypicalOpCode):
    _op = 0x43
    _name = 'cbit'
    _arguments_fmt = 'var_{0:0>2X}'
    _pops = 1
class TestBitOpCode(OpCode):
    _op = 0x44
    _name = 'tbit'
    _pops = 2
    _pushes = 1
    _fmt_decompile = 'test_bit({0}, {1})'
class SetBitsOpCode(TypicalOpCode):
    _op = 0x45
    _name = 'sbits'
    _arguments_fmt = 'var_{0:0>2X}'
    _pops = 3
    _variables = (True,)
    _fmt_decompile = 'set_bits({0}, {1}, {2}, {3})'
class GetBitsOpCode(OpCode):
    _op = 0x46
    _name = 'gbits'
    _pops = 3
    _pushes = 1
    _fmt_decompile = 'get_bits({0}, {1}, {2})'
class DataCharOpCode(OpCode):
    _op = 0x47
    _name = 'dchar'
    _pops = 1
    _pushes = 1
    _fmt_decompile = 'dchar({0})'
    _bounded = True
class DataByteOpCode(OpCode):
    _op = 0x48
    _name = 'dbyte'
    _pops = 1
    _pushes = 1
    _fmt_decompile = 'dbyte({0})'
    _bounded = True
class DataWordOpCode(OpCode):
    _op = 0x49
    _name = 'dword'
    _pops = 1
    _pushes = 1
    _fmt_decompile = 'dword({0})'
    _bounded = True
class SetBitArgumentOpCode(TypicalOpCode):
    _op = 0x4A
    _name = 'sbita'
    _arguments_fmt = 'arg_{0:X}'
    _pops = 1
    _fmt_decompile = 'set_bit(a{0}, {1})'
class ClearBitArgumentOpCode(TypicalOpCode):
    _op = 0x4B
    _name = 'cbita'
    _arguments_fmt = 'arg_{0:X}'
    _pops = 1
    _fmt_decompile = 'clear_bit(a{0}, {1})'
class SetBitsArgumentOpCode(TypicalOpCode):
    _op = 0x4C
    _name = 'sbitsa'
    _arguments_fmt = 'arg_{0:X}'
    _pops = 3
    _fmt_decompile = 'set_bits(a{0}, {1}, {2}, {3})'
class Ps4TouchOpCode(TypicalOpCode):
    _op = 0x4D
    _name = 'ps4tch'
    _pops = 1
    _pushes = 1
    _fmt_decompile = 'ps4_touchpad({0})'
    _bounded = True
    _constants = (PS4,)
class GetBatteryOpCode(OpCode):
    _op = 0x4E
    _name = 'gbatt'
    _pushes = 1
    _fmt_decompile = 'get_battery()'
class NopOpCode(OpCode):
    _op = 0x4F
    _name = 'nop'
    _fmt_decompile = 'NOP()'   
class GetPS4AuthTimeOutOpCode(OpCode):
    _op = 0x50
    _name = 'GetPS4AuthTimeout'
    _pushes = 1
    _fmt_decompile = 'ps4_authtimeout()'
class PS4OutReConnOpCode(OpCode):
    _op = 0x51
    _name = 'op_reconn'
    _fmt_decompile = 'output_reconnection()'     
class GetCtrlBtnOpCode(OpCode):
    _op = 0x52
    _name = 'GetCtrlBtnOpCode'
    _pushes = 1
    _fmt_decompile = 'get_ctrlbutton()'    

 


missing = {
}

opcodes = [
    MainEndOpCode,
    RemapOpCode,
    MainStartOpCode,
    AllocateOpCode,
    PushImmediateOpCode,
    PushOpCode,
    PopOpCode,
    WaitOpCode,
    JumpOpCode,
    JumpZeroOpCode,
    AndOpCode,
    OrOpCode,
    EqualOpCode,
    NotEqualOpCode,
    LessThanOpCode,
    LessThanEqualOpCode,
    GreaterThanOpCode,
    GreaterThanEqualOpCode,
    AddOpCode,
    SubtractOpCode,
    MultiplyOpCode,
    DivideOpCode,
    NotOpCode,
    GetRtimeOpCode,
    SetValOpCode,
    GetValOpCode,
    GetLvalOpCode,
    GetPtimeOpCode,
    EventPressOpCode,
    EventReleaseOpCode,
    TurnOffOpCode,
    SwapOpCode,
    BlockOpCode,
    SensitivityOpCode,
    SetLedOpCode,
    GetLedOpCode,
    SetRumbleOpCode,
    GetRumbleOpCode,
    LoadSlotOpCode,
    AbsOpCode,
    ResetLedOpCode,
    BlockRumbleOpCode,
    ResetRumbleOpCode,
    VmtCtrlOpCode,
    InverseOpCode,
    WiirOffScreenOpCode,
    PowOpCode,
    IntSqrtOpCode,
    StickizeOpCode,
    UnmapOpCode,
    DeadZoneOpCode,
    ModulusOpCode,
    SetPvarOpCode,
    GetPvarOpCode,
    CallOpCode,
    RetOpCode,
    PushArgumentOpCode,
    PopArgumentOpCode,
    SetLedxOpCode,
    GetLedxOpCode,
    GetConsoleOpCode,
    GetControllerOpCode,
    XorOpCode,
    PushIndexedOpCode,
    PopIndexedOpCode,
    GetSlotOpCode,
    SetBitOpCode,
    ClearBitOpCode,
    TestBitOpCode,
    SetBitsOpCode,
    GetBitsOpCode,
    DataCharOpCode,
    DataByteOpCode,
    DataWordOpCode,
    SetBitArgumentOpCode,
    ClearBitArgumentOpCode,
    SetBitsArgumentOpCode,
    Ps4TouchOpCode,
    GetBatteryOpCode,
    NopOpCode,
    GetPS4AuthTimeOutOpCode,
    PS4OutReConnOpCode,
    GetCtrlBtnOpCode
    
]
