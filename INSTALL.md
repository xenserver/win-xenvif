To install the XenServer Virtual Network Interface Device Driver onto a 
XenServer Windows guest VM:

*    Copy xenvif.sys, xenvif_coinst.dll and xenvif.inf onto the 
     guest VM 
*    Install xenbus.sys on the guest VM
*    Install xenvif.sys on the guest VM 
*    Copy dpinst.exe from the Windows driver kit into the same folder as
     xenvif.sys, xenvif_coinst.dll and xenvif.inf on the guest vm, ensuring 
     the version of dpinst.exe matches the architecture of the version 
     of Windows installed on your VM
*    As administrator, run dpinst.exe on the guest vm
*    If any warnings arise about unknown certificates, accept them

