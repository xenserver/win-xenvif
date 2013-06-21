XenNet - The XenServer Windows Virtual Network Interface Device Driver
==========================================

XenVif attaches to the XenBus device and provides a network interface for each 
virtual network device provided by the guest VM.  XenVif also provides the
support functions necessary for virtual network devices to communicate with the
Host network backend.

There is only one instance of a XenVif device per VM, no matter how many 
network interfaces it provides

Quick Start
===========

Prerequisites to build
----------------------

*   Visual Studio 2012 or later 
*   Windows Driver Kit 8 or later
*   Python 3 or later 

Environment variables used in building driver
-----------------------------

MAJOR\_VERSION Major version number

MINOR\_VERSION Minor version number

MICRO\_VERSION Micro version number

BUILD\_NUMBER Build number

SYMBOL\_SERVER location of a writable symbol server directory

KIT location of the Windows driver kit

PROCESSOR\_ARCHITECTURE x86 or x64

VS location of visual studio

Commands to build
-----------------

    git clone http://github.com/xenserver/win-xenvif
    cd win-xenvif
    .\build.py [checked | free]

Device tree diagram
-------------------

    XenNet XenNet
        |    | 
        XenVif
           |
        XenBus
           |
        PCI Bus      
