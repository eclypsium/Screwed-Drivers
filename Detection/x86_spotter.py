from ..util.lifter_helper import GymratLifter
from ..util.instr_helper import Instruction
from .. import register
import logging

from pyvex.lifting.util import Instruction, JumpKind, ParseError, Type

l = logging.getLogger(__name__)


class X86Instruction(Instruction): # pylint: disable=abstract-method
    pass

class Instruction_ENDBR(X86Instruction):
    name = "ENDBR"
    bin_format = '1111001100001111000111101111101b'

    def compute_result(self): # pylint: disable=arguments-differ
        # Perhaps, if one wanted to verify ENDBR behavior during compilation
        # Throw some CCall or whatever in here.
        if self.data['b'] == '1':
            l.debug("Ignoring ENDBR32 instruction at %#x.", self.addr)
        elif self.data['b'] == '0':
            l.debug("Ignoring ENDBR64 instruction at %#x.", self.addr)

class Instruction_RDMSR(X86Instruction):
    name = "RDMSR"
    bin_format = '0000111100110010'

    def compute_result(self): # pylint: disable=arguments-differ
        l.warning("Ignoring RDMSR instruction at %#x.", self.addr)
        # don't really care about value, just want to write to dest
        # regs to avoid false positives from data flow tracking
        # of previous register values
        self.put(self.constant(0, Type.int_64), 'rax')
        self.put(self.constant(0, Type.int_64), 'rdx')

class Instruction_WRMSR(X86Instruction):
    name = "WRMSR"
    bin_format = '0000111100110000'

    def compute_result(self): # pylint: disable=arguments-differ
        l.warning("Ignoring WRMSR instruction at %#x.", self.addr)

class Instruction_RDWRCR(X86Instruction):
    name = "RDWRCR"
    bin_format = '00001111001000d0mmgggrrr'

    def compute_result(self): # pylint: disable=arguments-differ
        if self.data['d'] == '1':
            l.warning("Ignoring WrCR instruction at %#x: mod=%s, reg=%s, rm=%s.", self.addr, self.data['m'], self.data['g'], self.data['r'])
        elif self.data['d'] == '0':
            l.warning("Ignoring RdCR instruction at %#x: mod=%s, reg=%s, rm=%s.", self.addr, self.data['m'], self.data['r'], self.data['g'])
            # don't really care about value, just want to write to dest
            # reg to avoid false positives from data flow tracking
            # of previous register value
            #self.put(self.constant(0, Type.int_64), int(self.data['g']))

class Instruction_RDWRCR8(X86Instruction):
    name = "RDWRCR8"
    bin_format = '0100010000001111001000d0mmgggrrr'

    def compute_result(self): # pylint: disable=arguments-differ
        if self.data['d'] == '1':
            l.warning("Ignoring WrCR8 instruction at %#x: mod=%s, reg=%s, rm=%s.", self.addr, self.data['m'], self.data['g'], self.data['r'])
        elif self.data['d'] == '0':
            l.warning("Ignoring RdCR8 instruction at %#x: mod=%s, reg=%s, rm=%s.", self.addr, self.data['m'], self.data['r'], self.data['g'])
            #self.put(self.constant(0, Type.int_64), int(self.data['g']))

class X86Spotter(GymratLifter):
    instrs = [
        Instruction_ENDBR,
        Instruction_RDMSR,
        Instruction_WRMSR,
        Instruction_RDWRCR,
        Instruction_RDWRCR8,
	]

register(X86Spotter, "X86")
register(X86Spotter, "AMD64")
