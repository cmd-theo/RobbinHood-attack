# PoC RobinHood Ransomware replication by using Aorus Gigabyte v1.34

## Description

This exploit first get a handle on the gigabyte driver and use IOCTL's code to allocate memory and put our shellcode in the kernel memory.
The shellcode himself is making a loop on EPROCESS structures in order to find the token
associated to the "system" process and give this token to our actual cmd.
All the basic security features are disabled from this point.
Then the mimikatz driver is downloaded and loaded to the system.
Windows defender is totally stopped from this point in order to cipher all the file present on the desktop.
## Usage

After building the project you need to use the InjectRSA executable to embed your public key in the exploit executable. Then you simply launch the exploit RobbinHood.exe.
 * > InjectRSA.exe pub.key RobbinHood.exe
 * > RobbinHood.exe
 
## Obfuscation methods

This exploit is not built-in obfuscated, it's is possible to apply Compile-time obfuscation by installing the [Obfuscator-LLVM project] (https://github.com/heroims/obfuscator).
The following obfuscation compilation directives was tested and approved :
```
-D__CUDACC__ -D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH -mllvm -bcf -mllvm -bcf_prob=100 -mllvm -bcf_loop=3 
-mllvm -sub -mllvm -sub_loop=2 -mllvm -fla -mllvm -split_num=10 -mllvm -aesSeed=DEADBEEFDEADBEEFDEADBEEFDEADBEEF
```

## Technical Information
Vulnerable driver : Gigabyte AORUS Graphics Engine v1.34 

Required package for the driver : Visual C++ Redistribuable 2012 x86

Developed in Visual Studio 2013 Community

Tested on : Windows 8.1 x64 6.3.9600 

## Credits

- [ ] [Ruben Santamarta : Exploiting Common Flaw in Drivers (2007)]
- [ ] [CVE-2018-19320-LPE] (https://github.com/hmnthabit/CVE-2018-19320-LPE)
- [ ] [DisableSVC] (https://raw.githubusercontent.com/rbmm/DisableSvc/main/x64/btsp.exe)
