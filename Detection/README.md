# Wormhole Driver Detection Framework

This wormhole driver detection script currently depends on python3, angr
symbolic execution framework, radare2, and objdump.

Easiest way to set it up is via virtualenv.

Installations for Ubuntu are:

```
$ sudo apt-get install python3-dev libffi-dev build-essential virtualenvwrapper radare2 binutils
$ mkvirtualenv --python=$(which python3) angr && pip install angr && pip install r2pipe
```

This will install angr and it's python dependencies to .virtualenv/angr and
launch a shell in this environment.

To run the script, just pass it the driver filename as the sole argument like:

```
(angr) $ python3 wormhole.py drivers/driver.sys
```

## Tuning the analysis

There are some CHECK_xxx variables at the top of the script to enable/disable
looking for specific operations. The IN/OUT detection is disabled by default
because it is generally a lower-severity issue and more likely to cause the
script to run out of memory due to (potentially misdisassembled) IN/OUT
opcodes that aren't easy to determine if they're reachable or not.

In addition, the n=100 argument for the sm.explore() calls in find_handlers()
and runcheck() specify how many state steps to simulate before giving up.

These have been arbitrarily limited to 100 state steps to reduce the likelihood
of running out of memory, but may make the analysis exit before finding valid
paths that exist in the driver.

If there are issues with detecting the IOCTL handler in WDM drivers, it's
generally safe to increase the limit in find_handlers() and I've run it at
n=500 without issues.

Increasing the limit in runcheck() is more likely to result in running out of
memory, but may help find additional valid paths.

## Problems with VEX IR lifting

angr uses pyvex, which uses VEX from the Valgrind project for intermediate
representation lifting. VEX doesn't recognize some privileged X86 opcodes,
such as rdmsr, wrmsr, mov XXX, crN, and mov crN,XXX. This causes basic
blocks containing these opcodes to be disassembled incorrectly and breaks
the control flow tracking for these paths.

However, pyvex has added the ability to implement VEX IR lifters in python
which can be used to fill gaps in the native VEX implementation.

As a workaround, I've added several new entries to pyvex's gymrat lifter to
recognize read/write msr and read/write control registers.

The included x86_spotter.py script should replace pyvex/lifting/gym/x86_spotter.py
within the pyvex tree.

If using the mkvirtualenv command from above, that should be at:

```
~/.virtualenvs/angr/lib/python3.6/site-packages/pyvex/lifting/gym/x86_spotter.py
```

## How it works

The basic idea for this tool is:

1. find address of the ioctl handling function
2. find addresses of potentially dangerous operations, such as rdmsr/wrmsr
3. attempt to determine if there's a way to reach #2 from #1
4. if so, check where the arguments came from

In order to find the ioctl handling function, we first attempt to determine
whether it's a WDM or WDF driver by looking for specific imported
function names which are used to initialize drivers.

WDM drivers are easier to process and for those we:

1. build a state which will be used to step forward from the driver entry
   point create a symbolic buffer to hold the contents of the _DRIVER_OBJECT
   structure which is passed to the driver entry point.
2. set a memory write breakpoint on the ->MajorFunction[IRP_MJ_DEVICE_CONTROL]
   function pointer which will be filled in with the address of the ioctl
   handler
3. step forward exploring states for 500 steps
4. check if we found a write to ->MajorFunction[IRP_MJ_DEVICE_CONTROL] with
   the address of the ioctl handler

WDF drivers are a little more complex, but we should be able to find the
ioctl handler function via some additional hooking and indirection.  That's
currently unimplemented and left as an exercise for the reader.

Once we have the ioctl handling function, we search for interesting target
operations.  I was having issues getting the disassembly functions in angr
and radare2 to work reliably with a broad array of binaries, so for expediency,
the code currently just uses objdump to get addresses of instructions we're
interested in.

The current sole exception is that we're using radare2 to look for callers
to MmMapIoSpace() rather than just searching for paths to the imported
MmMapIoSpace() symbol.  We want to get the address of each call opcode that
jumps to MmMapIoSpace() because we can have multiple callers and want to
check them all.

In order to check if we can reach the target operations from the ioctl handler
address, we create symbolic buffers for the _DEVICE_OBJECT and _IRP structures
which are passed to the ioctl handler.

To provide better results, we fill in the following structures within the IRP
separately, so they get their own names:

- Irp->AssociatedIrp.SystemBuffer which is filled from InBuffer
- IrpSp structure
- IrpSp->Parameters.DeviceIoControl structure
- IrpSp->Parameters.DeviceIoControl->Type3InputBuffer pointer

From there, we just create a simulation manager to explore states until we
reach the target operation address.

If a path is found, we check the state and see if the arguments were symbolic
and look for identified constraints.

## Examples

Here's an example of the current output from the AsrDrv10.sys driver:

```
[AsrDrv10.sys] Attempting to find path from 110a8 to WrMSR at 11deb
[AsrDrv10.sys] Found path from 110a8 to 11deb
Backtrace:
Frame 0: 0x11664 => 0x11d84, sp = 0x7fffffffffeffc8
Frame 1: 0x0 => 0x0, sp = 0xffffffffffffffff
RIP: 11deb
IOCTL NUM: 222878 from <BV32 irsp_params_ioctl_num_7176_32>
MSR ADDR: symbolic=False, value=<BV32 0x186>
MSR DATA1: symbolic=False, value=<BV32 0x0>
MSR DATA2: symbolic=False, value=<BV32 0x43003c>
Constraints:
```

In this example, we've identified that there's a wrmsr opcode at 0x11deb and
we've successfully found a path there.

The ioctl number was identified to be 0x222878, but the address and data for
this path are *not* taken from the ioctl InBuffer and instead are 0x186 and
0x0:0x43003c.

No additional constraints were identified, but this wrmsr does not appear to
be arbitrary and we can move on to others in the report.

Here's another example from AsrDvr10.sys:

```
[AsrDrv10.sys] Attempting to find path from 110a8 to WrMSR at 113e8
[AsrDrv10.sys] Found path from 110a8 to 113e8
Backtrace:
Frame 0: 0x0 => 0x0, sp = 0xffffffffffffffff
RIP: 113e8
IOCTL NUM: 22284c from <BV32 irsp_params_ioctl_num_599_32>
Found WRMSR with arbitrary address AND value!
MSR ADDR: symbolic=True, value=<BV32 ioctl_inbuf_590_8192[95:64]>
MSR DATA1: symbolic=True, value=<BV32 ioctl_inbuf_590_8192[127:96]>
MSR DATA2: symbolic=True, value=<BV32 ioctl_inbuf_590_8192[31:0]>
Constraints:
```

In this case, we've detected a wrmsr opcode at address 0x113e8 and the ioctl
number is 0x22284c.

Unlike the previously detected wrmsr, the arguments for this one are symbolic
and have been taken from the ioctl InBuffer. This ioctl is vulnerable.

The MSR address is the second DWORD and the value is taken from the next first
and third DWORDs.  No additional constraints were identified.

A third example from AsrDvr10.sys:

```
[AsrDrv10.sys] Attempting to find path from 110a8 to WrCR at 11731
[AsrDrv10.sys] Found path from 110a8 to 11731
Backtrace:
Frame 0: 0x0 => 0x0, sp = 0xffffffffffffffff
RIP: 11731
IOCTL NUM: 222870 from <BV32 irsp_params_ioctl_num_1843_32>
Found write to control register with arbitrary value!
Write CR: target=cr4, symbolic=True, value=<BV64 ioctl_inbuf_1834_8192[127:64]>
Constraints:
  Input Buffer: <Bool ioctl_inbuf_1834_8192[31:0] == 0x4>
```

For this case, we've detected that there's a write to CR4 at address 0x11731
and the ioctl number is 0x222870.

In many cases, functionality to write to multiple control registers is bundled
together under a single ioctl and we've detected an additional constraint that
the first DWORD must be 4.

Examining the report for other detected MOV CRn opcodes in this driver, we'll
find that there is also support for writing to CR0, CR3, and CR8 via this
ioctl and the value to be written will be a QWORD starting 8 bytes into the
Input Buffer.

## Limitations

1. Current version of the script finds arguments passed to read primitives
   like addresses and sizes, but does not determine if the result of the read
   is placed back into the SystemBuffer and copied to the OutBuffer to return
   the value to the caller in userspace.

   Need to verify that through inspection or via writing a simple poc.

2. Finding ioctl handler address in WDF drivers is currently not supported.

   WDF drivers are a little more complex, but we should be able to create a
   hook for WdfVersionBind() which builds the WdfFunctions function pointer
   table and automatically hook calls to WdfFunctions[WdfIoQueueCreate] to
   determine the address of the ioctl handler function.

2. Sometimes, it blows up and runs out of memory for non-obvious reasons

   I've added code to set a hard resource limit at 62GB to keep from
   DOSing myself.

   When I started developing this script, I would completely run out of
   memory and the dhcp client wouldn't be able to renew the lease and my box
   would drop off the network and stop responding to ssh.

   Set this limit to whatever is appropriate for your analysis system.

   A better approach would be to start at the target opcode and trace paths
   backwards, but I haven't spent enough time with angr to get its Backward
   Slicing simulation strategy working in a useful manner.

3. If arbitrary helper functions are used and there are multiple paths to call
   them, not all possible paths might be detected.

   As an example, if the wrmsr opcode is contained inside a write_msr(addr, value)
   function and there are multiple callers to that function, paths that take
   more state steps to reach the target opcode will not be found because the
   script currently stops as soon as it reaches the shortest set of paths from
   ioctl handler to target address.

   For example, in the following code, more state transitions occur before
   the call to write_msr with addr1/value1 than addr2/value2 and the breadth-first
   search being performed by the .explore() simulation manager will encounter
   the write_msr() call with addr2/value2 first and exit the execution run.

```c
   if (foo()) {
     if (bar()) {
       write_msr(addr1, value1);
     }
   } else {
       write_msr(addr2, value2);
   }
```

   This can be worked around by adding the address of calls to the helper
   function which are traversed with short paths to avoid_addrs list to force
   alternate paths to be evaluated.

   In the above example, the address of call to write_msr(addr2, value2) could
   be added to avoid_addrs to force evaluation of other call to helper function.

4. Sometimes constraints are a mess even after simplification.

   Here's an example constraint detected from discovering a path to a mov cr8
   opcode in currently unnamed driver:

> <Bool (if (type3_buf_9_8192[61:0] == 0x11) then 113 else (if (type3_buf_9_8192[61:0] == 0x3a) then 34 else (if (type3_buf_9_8192[61:0] == 0x7) then 129 else (if (type3_buf_9_8192[61:0] == 0x10) then 113 else (if (type3_buf_9_8192[61:0] == 0x30) then 217 else (if (type3_buf_9_8192[61:0] == 0x1d) then 113 else (if (type3_buf_9_8192[61:0] == 0x26) then 139 else (if (type3_buf_9_8192[61:0] == 0x6) then 113 else (if (type3_buf_9_8192[61:0] == 0x33) then 180 else (if (type3_buf_9_8192[61:0] == 0x13) then 71 else (if (type3_buf_9_8192[61:0] == 0x1c) then 25 else (if (type3_buf_9_8192[61:0] == 0x29) then 247 else (if (type3_buf_9_8192[61:0] == 0x9) then 199 else (if (type3_buf_9_8192[61:0] == 0x32) then 105 else (if (type3_buf_9_8192[61:0] == 0x12) then 113 else (if (type3_buf_9_8192[61:0] == 0x1f) then 113 else (if (type3_buf_9_8192[61:0] == 0x28) then 216 else (if (type3_buf_9_8192[61:0] == 0x8) then 164 else (if (type3_buf_9_8192[61:0] == 0x35) then 113 else (if (type3_buf_9_8192[61:0] == 0x15) then 141 else (if (type3_buf_9_8192[61:0] == 0x1e) then 113 else (if (type3_buf_9_8192[61:0] == 0x27) then 184 else (if (type3_buf_9_8192[61:0] == 0x2b) then 113 else (if (type3_buf_9_8192[61:0] == 0xb) then 113 else (if (type3_buf_9_8192[61:0] == 0x1a) then 214 else (if (type3_buf_9_8192[61:0] == 0x14) then 106 else (if (type3_buf_9_8192[61:0] == 0x34) then 113 else (if (type3_buf_9_8192[61:0] == 0x21) then 113 else (if (type3_buf_9_8192[61:0] == 0x1) then 35 else (if (type3_buf_9_8192[61:0] == 0x2a) then 22 else (if (type3_buf_9_8192[61:0] == 0xa) then 113 else (if (type3_buf_9_8192[61:0] == 0x37) then 158 else (if (type3_buf_9_8192[61:0] == 0x17) then 113 else (if (type3_buf_9_8192[61:0] == 0x20) then 113 else (if (type3_buf_9_8192[61:0] == 0x2d) then 113 else (if (type3_buf_9_8192[61:0] == 0xd) then 233 else (if (type3_buf_9_8192[61:0] == 0x36) then 60 else (if (type3_buf_9_8192[61:0] == 0x16) then 113 else (if (type3_buf_9_8192[61:0] == 0x23) then 80 else (if (type3_buf_9_8192[61:0] == 0x3) then 98 else (if (type3_buf_9_8192[61:0] == 0x2c) then 113 else (if (type3_buf_9_8192[61:0] == 0xc) then 113 else (if (type3_buf_9_8192[61:0] == 0x39) then 247 else (if (type3_buf_9_8192[61:0] == 0x19) then 175 else (if (type3_buf_9_8192[61:0] == 0x31) then 30 else (if (type3_buf_9_8192[61:0] == 0x22) then 113 else (if (type3_buf_9_8192[61:0] == 0x2) then 66 else (if (type3_buf_9_8192[61:0] == 0x2f) then 93 else (if (type3_buf_9_8192[61:0] == 0xf) then 40 else (if (type3_buf_9_8192[61:0] == 0x38) then 209 else (if (type3_buf_9_8192[61:0] == 0x18) then 113 else (if (type3_buf_9_8192[61:0] == 0x25) then 107 else (if (type3_buf_9_8192[61:0] == 0x5) then 113 else (if (type3_buf_9_8192[61:0] == 0x2e) then 113 else (if (type3_buf_9_8192[61:0] == 0xe) then 8 else (if (type3_buf_9_8192[61:0] == 0x1b) then 253 else (if (type3_buf_9_8192[61:0] == 0x3b) then 77 else (if (type3_buf_9_8192[61:0] == 0x24) then 53 else (if (type3_buf_9_8192[61:0] == 0x4) then 113 else 192))))))))))))))))))))))))))))))))))))))))))))))))))))))))))) == 217>

   It's sometimes faster to just write a poc than to try to decipher what's
   going on with the constraints in some extreme cases.
