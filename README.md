ScrewedDrivers
======

### General information
We have created this repository as a centralized source of knowledge which contains a list of drivers determined to be vulnerable as well as example code for how to use this kind of functionality.

***
### DRIVERS.md
This file contains a list of drivers, hashes, and who they are signed by.  In some cases, links to advisories and other research we found discussing these drivers will be included as well.

### ADVISORIES.md
Vendor advisories will be published here once they are made public.

# Code samples:
### C#
#### LoadDriverAsService: 
This is an example of an application to automate the loading of a driver as a service in Windows, if run as user it will prompt a UAC. We used this to help us load various drivers for experimentation.
#### exampleApplication: 
An example of how to use an ASrock driver to read an MSR, including all the relevant imports from Windows.

### Powershell
#### ASRock_readmsr.ps1:
Based on FuzzySec's excellent writeup and example, this code does the same as the C# "exampleApplication", except written in PowerShell.

#### ASRock_readcr.ps1:
Example of reading Control Registers from PowerShell

#### ASRock_writecr.ps1:
Example of writing Control Registers from PowerShell

#### ASRock_kaslr.ps1:
Example of reading LSTAR MSR and CR3 to find Windows kernel syscall entry point and kernel page table base, defeating KASLR

#### ASRock_check_smep.ps1:
Checks if SMEP is enabled on each CPU from PowerShell

#### ASRock_disable_smep.ps1:
Disables SMEP temporarily from PowerShell

#### ASRock_disable_kern_wp.ps1:
Disables CR0 Write Protect bit temporarily from PowerShell 

# Detection
## wormhole.py
This is a script written using the angr dynamic analysis framework to detect this kind of vulnerability in drivers.

## x86_spotter.py
This file contains gymrat spotter functions to address limitations in the pyvex framework angr depends on.

