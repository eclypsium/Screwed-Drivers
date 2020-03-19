#!/usr/bin/python3

# Wormhole driver analysis framework
#
# Copyright (C) 2019 Eclypsium
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.

import angr
import claripy
import subprocess
import resource
import sys
import re
import os
import r2pipe

import logging

#logging.getLogger('angr').setLevel('DEBUG')

CHECK_MSR          = True
CHECK_CR           = True
CHECK_DR           = True
CHECK_INOUT        = False
CHECK_MMMAPIOSPACE = True

gb_limit = 60

drv_obj_addr     = 0x3000000
dev_obj_addr     = 0x4000000
irp_addr         = 0x5000000
irsp_addr        = 0x6000000
ioctl_inbuf_addr = 0x7000000
type3_buf_addr   = 0x9000000

# these are globals so that we can access them from angr callbacks
global which
global ioctl_handlers
global targets

which = ""
ioctl_handlers = [ ]

class returnzero(angr.SimProcedure):
	def run(self):
		return 0x0

class returnone(angr.SimProcedure):
	def run(self):
		return 0x1

def ioctl_handler_write_hook(state):
	global ioctl_handlers

	ioctl_handler_addr = state.solver.eval(state.inspect.mem_write_expr)
	if ioctl_handler_addr not in ioctl_handlers:
		ioctl_handlers.append(ioctl_handler_addr)

	print("IOCTL_HANDLER = %x" % ioctl_handler_addr)

def check_wrmsr(found_path):
	if (found_path.regs.ecx.symbolic and found_path.regs.edx.symbolic and found_path.regs.eax.symbolic):
		print("Found WRMSR with arbitrary address AND value!")

	if (found_path.regs.ecx.symbolic and (not found_path.regs.edx.symbolic) and (not found_path.regs.eax.symbolic)):
		print("Found WRMSR with arbitrary address and fixed value!")

	print("MSR ADDR: symbolic=%s, value=%s" % (found_path.regs.ecx.symbolic, found_path.regs.ecx))
	print("MSR DATA1: symbolic=%s, value=%s" % (found_path.regs.edx.symbolic, found_path.regs.edx))
	print("MSR DATA2: symbolic=%s, value=%s" % (found_path.regs.eax.symbolic, found_path.regs.eax))

def check_rdmsr(found_path):
	if found_path.regs.ecx.symbolic:
		print("Found RDMSR with arbitrary address!")

	print("MSR ADDR: symbolic=%s, value=%s" % (found_path.regs.ecx.symbolic, found_path.regs.ecx))

def check_wrcr(found_path):
	eval_str = "found_path.regs.%s" % targets[found_path.solver.eval(found_path.regs.rip)]["source"]
	source = eval(eval_str)
	target = targets[found_path.solver.eval(found_path.regs.rip)]["target"]
	if source.symbolic:
		print("Found write to control register with arbitrary value!")
	print("Write CR: target=%s, symbolic=%s, value=%s" % (target, source.symbolic, source))

def check_rdcr(found_path):
	source = targets[found_path.solver.eval(found_path.regs.rip)]["source"]
	print("Read CR: source=%s" % source)

def check_wrdr(found_path):
	eval_str = "found_path.regs.%s" % targets[found_path.solver.eval(found_path.regs.rip)]["source"]
	source = eval(eval_str)
	target = targets[found_path.solver.eval(found_path.regs.rip)]["target"]
	if source.symbolic:
		print("Found write to debug register with arbitrary value!")
	print("Write DR: target=%s, symbolic=%s, value=%s" % (target, source.symbolic, source))

def check_rddr(found_path):
	source = targets[found_path.solver.eval(found_path.regs.rip)]["source"]
	print("Read DR: source=%s" % source)

def check_out(found_path):
	source_str = "found_path.regs.%s" % targets[found_path.solver.eval(found_path.regs.rip)]["source"]
	source = eval(source_str)
	target_str = "found_path.regs.%s" % targets[found_path.solver.eval(found_path.regs.rip)]["target"]
	target = eval(target_str)
	if source.symbolic and target.symbolic:
		print("[%s] Found OUT with arbitrary address and value!" % which)
	elif source.symbolic:
		target_addr = found_path.solver.eval(target)
		if target_addr == 0xcf8:
			print("[%s] Found PCI access with arbitrary address!" % which)
		elif target_addr == 0xcfc:
			print("[%s] Found PCI write with arbitrary value!" % which)
		else:
			print("[%s] Found OUT with arbitrary value!" % which)
	elif target.symbolic:
		print("[%s] Found OUT with arbitrary address!" % which)

	print("OUT ADDR: symbolic=%s, addr=%s" % (target.symbolic, target))
	print("OUT DATA: symbolic=%s, value=%s" % (source.symbolic, source))

def check_in(found_path):
	source_str = "found_path.regs.%s" % targets[found_path.solver.eval(found_path.regs.rip)]["source"]
	source = eval(source_str)
	if source.symbolic:
		print("[%s] Found IN with arbitrary address!" % which)

	print("IN ADDR: symbolic=%s, addr=%s" % (source.symbolic, source))

def check_mmmapiospace(found_path):
	if (found_path.regs.rcx.symbolic and found_path.regs.edx.symbolic):
		print("Found MmMapIoSpace with arbitrary address AND size!")
	elif (found_path.regs.rcx.symbolic and (not found_path.regs.edx.symbolic)):
		print("Found MmMapIoSpace with arbitrary address and fixed size!")

	print("MmMapIoSpace Address: symbolic=%s, value=%s" % (found_path.regs.rcx.symbolic, found_path.regs.rcx))
	print("MmMapIoSpace Size: symbolic=%s, value=%s" % (found_path.regs.edx.symbolic, found_path.regs.edx))

def runcheck(ioctl_handler_addr, target_addr, avoid_addrs, check_func):

#	cfg = p.analyses.CFG(resolve_indirect_jumps=True)
#	for addr,func in cfg.kb.functions.items():
#		print("%s = %x" % (func, addr))

	angr_add_options = {angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
	angr_remove_options = {angr.options.LAZY_SOLVES}
	state = p.factory.call_state(addr=ioctl_handler_addr, add_options=angr_add_options, remove_options=angr_remove_options)

	dev_obj_buf = claripy.BVS('device_object', 8*0x150).reversed
	irp_buf = claripy.BVS('irp', 8*0xd0).reversed
	ioctl_inbuf = claripy.BVS('ioctl_inbuf', 1024*8).reversed
	type3_buf = claripy.BVS('type3_buf', 1024*8).reversed

	irsp_majfunc = claripy.BVS('irsp_major_function', 8).reversed
	irsp_minfunc = claripy.BVS('irsp_minor_function', 8).reversed
	irsp_flags = claripy.BVS('irsp_flags', 8).reversed
	irsp_control = claripy.BVS('irsp_control', 8).reversed
	irsp_undefined = claripy.BVS('irsp_undefined', 8*4).reversed

	irsp_params_outbuf_size = claripy.BVS('irsp_params_outbuf_size', 8*4).reversed
	irsp_params_inbuf_size = claripy.BVS('irsp_params_inbuf_size', 8*4).reversed
	irsp_params_ioctl_num = claripy.BVS('irsp_params_ioctl_num', 8*4).reversed

	# special handling for DeviceIoControl Type3InputBuffer
	irsp_params_type3_inbuf = claripy.BVV(type3_buf_addr, 8*8).reversed

	irsp_parameters= claripy.Concat(irsp_params_outbuf_size, irsp_undefined, irsp_params_inbuf_size, irsp_undefined, irsp_params_ioctl_num, irsp_undefined, irsp_params_type3_inbuf)

	irsp_devobj_ptr = claripy.BVS('irsp_devobj', 8*8).reversed
	irsp_fileobj_ptr = claripy.BVS('irsp_fileobj', 8*8).reversed
	irsp_cmpl_routine = claripy.BVS('irsp_completion_routine', 8*8).reversed
	irsp_context = claripy.BVS('irsp_context', 8*8).reversed

	irsp = claripy.Concat(irsp_majfunc, irsp_minfunc, irsp_flags, irsp_control, irsp_undefined, irsp_parameters, irsp_devobj_ptr, irsp_fileobj_ptr, irsp_cmpl_routine, irsp_context)

	state.memory.store(dev_obj_addr, dev_obj_buf)
	state.memory.store(irp_addr, irp_buf)
	state.memory.store(ioctl_inbuf_addr, ioctl_inbuf)
	state.memory.store(irsp_addr, irsp)
	state.memory.store(type3_buf_addr, type3_buf)

	state.regs.rcx = dev_obj_addr
	state.regs.rdx = irp_addr
	state.mem[irp_addr+0x18].uint64_t = ioctl_inbuf_addr
	state.mem[irp_addr+0xb8].uint64_t = irsp_addr

	sm = p.factory.simulation_manager(state)

	sm.explore(find=target_addr, n=100, avoid=avoid_addrs)

	if sm.found:
		for found in sm.found:
			print("[%s] Found path from %x to %x" % (which, ioctl_handler_addr, target_addr))

			found.solver.simplify()

			print(found.callstack)
			print("RIP: %x" % state.solver.eval(found.regs.rip))
			print("IOCTL NUM: %x from %s" % (found.solver.eval(found.mem[irsp_addr+0x18].uint32_t.resolved), found.mem[irsp_addr+0x18].uint32_t.resolved))

			check_func(found)

			constraints = found.solver.constraints
			print("Constraints:")
			for constraint in constraints:
				constraint_str = "%s" % constraint
				if "inbuf_size" in constraint_str:
					print("  Input Buffer Size: %s" % constraint_str)
				elif "outbuf_size" in constraint_str:
					print("  Output Buffer Size: %s" % constraint_str)
				elif "inbuf" in constraint_str:
					print("  Input Buffer: %s" % constraint_str)
				elif "ioctl_num" in constraint_str:
					pass
				elif "major_function" in constraint_str:
					pass
				else:
					print("  %s" % constraint_str)
	else:
		print("[%s] Path from %x to %x NOT FOUND" % (which, ioctl_handler_addr, target_addr))

def determine_driver_type(p, r2):

	driver_type = ""

	iocreatedevice_addr = p.loader.find_symbol('IoCreateDevice')
	wdfversionbind_addr = p.loader.find_symbol('WdfVersionBind')

	if iocreatedevice_addr:
		print("Detected WDM driver: %s" % iocreatedevice_addr)
		driver_type = "wdm"
	elif wdfversionbind_addr:
		print("Detected WDF driver: %s" % wdfversionbind_addr)
		driver_type = "wdf"

	return driver_type

def find_avoids(p, r2):
	avoid_addrs = []

	kebugcheckex_addr = p.loader.find_symbol('KeBugCheckEx')
	if kebugcheckex_addr:
		print("Avoid : %s" % kebugcheckex_addr)
		avoid_addrs.append(kebugcheckex_addr.rebased_addr)

	return avoid_addrs

def hook_to_returnzero(p, symbol):
	sym_addr = p.loader.find_symbol(symbol)
	if sym_addr:
		p.hook_symbol(symbol, returnzero())

def hook_to_returnone(p, symbol):
	sym_addr = p.loader.find_symbol(symbol)
	if sym_addr:
		p.hook_symbol(symbol, returnone())

def find_handlers(p, r2, driver_type, avoid_addrs):
	global ioctl_handlers

	ioctl_handlers = []

	if driver_type == "wdm":
		angr_add_options = {angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
		angr_remove_options = {angr.options.LAZY_SOLVES}
		state = p.factory.entry_state(add_options=angr_add_options, remove_options=angr_remove_options)

		drv_obj_buf = claripy.BVS('driver_object', 8*0x150).reversed

		state.memory.store(drv_obj_addr, drv_obj_buf)
		state.regs.rcx = drv_obj_addr

		state.inspect.b('mem_write', mem_write_address=drv_obj_addr+0xe0, when=angr.BP_AFTER, action=ioctl_handler_write_hook)

		sm = p.factory.simulation_manager(state)
		sm.explore(avoid=avoid_addrs, n=100)

	if len(ioctl_handlers) == 0:
		print("Couldn't find ioctl handlers!")

	# make sure to mark ioctl handlers as functions to improve radare disassembly
	for ioctl_handler in ioctl_handlers:
		r2.cmd("s 0x%x" % ioctl_handler)
		r2.cmd("af 0x%x" % ioctl_handler)

	# increase max basic block size
	r2.cmd("e anal.bb.maxsize = 4096")
	# kick off auto analysis
	r2.cmd("aaaaaa")

	return ioctl_handlers

def find_targets(p, r2, filename):
	command = "objdump -d %s" % filename
	proc = subprocess.Popen([command], shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, encoding='utf8')

	targets = { }
	for line in proc.stdout:
		target = { }
		if CHECK_MSR:
			if "wrmsr" in line:
				target = {"type":"WrMSR", "check_func":check_wrmsr}

			if "rdmsr" in line:
				target = {"type":"RdMSR", "check_func":check_rdmsr}

		if CHECK_CR:
			# objdump defaults to gcc syntax, not intel
			m = re.search("%([a-z0-9]+),%(cr[0-9])", line)
			if m:
				wrcr_source = m.group(1)
				wrcr_target = m.group(2)
				target = {"type":"WrCR", "check_func":check_wrcr, "source":wrcr_source, "target":wrcr_target}

			# objdump defaults to gcc syntax, not intel
			m = re.search("%(cr[0-9]),%([a-z0-9]+)", line)
			if m:
				rdcr_source = m.group(1)
				target = {"type":"RdCR", "check_func":check_rdcr, "source":rdcr_source}

		if CHECK_DR:
			# objdump defaults to gcc syntax, not intel
			m = re.search("%([a-z0-9]+),%(db[0-9]+)", line)
			if m:
				wrdr_source = m.group(1)
				wrdr_target = m.group(2)
				target = {"type":"WrDR", "check_func":check_wrdr, "source":wrdr_source, "target":wrdr_target}

			# objdump defaults to gcc syntax, not intel
			m = re.search("%(db[0-9]+),%([a-z0-9]+)", line)
			if m:
				rddr_source = m.group(1)
				target = {"type":"RdDR", "check_func":check_rddr, "source":rddr_source}

		if CHECK_INOUT:
			# objdump defaults to gcc syntax, not intel
			m = re.search("out[ \t]+%([a-z0-9]+),\(%([a-z0-9]+)\)$", line)
			if m:
				out_source = m.group(1)
				out_target = m.group(2)
				target = {"type":"OUT", "check_func":check_out, "source":out_source, "target":out_target}

			# objdump defaults to gcc syntax, not intel
			m = re.search("in[ \t]+\(%([a-z0-9]+)\),%([a-z0-9]+)$", line)
			if m:
				in_source = m.group(1)
				target = {"type":"IN", "check_func":check_in, "source":in_source}

		if target:
			target_addr = int(line.strip().split(":")[0], 16)
			targets[target_addr] = target

	if CHECK_MMMAPIOSPACE:
		xrefs = r2.cmdj("axtj sym.imp.ntoskrnl.exe_MmMapIoSpace")
		for xref in xrefs:
			target = {"type":"MmMapIoSpace", "check_func":check_mmmapiospace}
			targets[xref["from"]] = target

	print("Locations to check:")
	if CHECK_MMMAPIOSPACE:
		print("MmMapIoSpace: %s" % [ ("0x%x" % k) for k,v in targets.items() if v["type"] == "MmMapIoSpace" ])
	if CHECK_MSR:
		print("Write MSR: %s" % [ ("0x%x" % k) for k,v in targets.items() if v["type"] == "WrMSR" ])
		print("Read MSR: %s" % [ ("0x%x" % k) for k,v in targets.items() if v["type"] == "RdMSR" ])
	if CHECK_CR:
		print("Write CR: %s" % [ ("0x%x" % k) for k,v in targets.items() if v["type"] == "WrCR" ])
		print("Read CR: %s" % [ ("0x%x" % k) for k,v in targets.items() if v["type"] == "RdCR" ])
	if CHECK_DR:
		print("Write DR: %s" % [ ("0x%x" % k) for k,v in targets.items() if v["type"] == "WrDR" ])
		print("Read DR: %s" % [ ("0x%x" % k) for k,v in targets.items() if v["type"] == "RdDR" ])
	if CHECK_INOUT:
		print("OUT: %s" % [ ("0x%x" % k) for k,v in targets.items() if v["type"] == "OUT" ])
		print("IN: %s" % [ ("0x%x" % k) for k,v in targets.items() if v["type"] == "IN" ])

	return targets

# angr can easily hit a combinatorial state explosion and run out of
# memory, so we'll set some limits
rsrc = resource.RLIMIT_DATA

soft, hard = resource.getrlimit(rsrc)
print('RLIMIT_DATA: %d, %d' % (soft, hard))

# set process limits
print("Setting process limits to %dGB" % (gb_limit))
resource.setrlimit(rsrc, (gb_limit*1024*1024*1024, gb_limit*1024*1024*1024+4096))

soft, hard = resource.getrlimit(rsrc)
print('RLIMIT_DATA: %d, %d' % (soft, hard))

for filename in sys.argv[1:]:
	which = os.path.basename(filename)

	print("---------------------------------------");
	print("[%s] Filename: %s" % (which, filename))

	if not os.path.isfile(filename):
		print("%s is not a plain file, skipping!" % filename)
		continue

	p = angr.Project(filename, auto_load_libs=False)

	r2 = r2pipe.open(filename)

	driver_type = determine_driver_type(p, r2)
	if not driver_type:
		print("Couldn't determine driver type!")
		continue

	avoid_addrs = find_avoids(p, r2)

	ioctl_handlers = find_handlers(p, r2, driver_type, avoid_addrs)

	hook_to_returnzero(p, 'KeStallExecutionProcessor')
	hook_to_returnzero(p, 'KeDelayExecutionThread')
	hook_to_returnzero(p, 'DbgPrintEx')
	hook_to_returnone(p, 'MmIsAddressValid')	# only checks if page is present, not if it's userspace or kernel

	targets = find_targets(p, r2, filename)

	for ioctl_handler_addr in ioctl_handlers:
		for target_addr,target_details in targets.items():
			print("---------------------------------------");
			print("[%s] Attempting to find path from %x to %s at %x" % (which, ioctl_handler_addr, target_details["type"], target_addr))
			runcheck(ioctl_handler_addr, target_addr, avoid_addrs, target_details["check_func"])
