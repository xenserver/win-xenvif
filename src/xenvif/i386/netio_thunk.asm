        				page    ,132
        				title   Netio Redirections

        				.686p
        				.model  FLAT
        				.code
	
					extrn	_NetioGetUnicastIpAddressTable:dword
	
        				public _GetUnicastIpAddressTable@8
_GetUnicastIpAddressTable@8		proc
					jmp 	_NetioGetUnicastIpAddressTable
_GetUnicastIpAddressTable@8		endp

					extrn	_NetioNotifyUnicastIpAddressChange:dword

					public 	_NotifyUnicastIpAddressChange@20
_NotifyUnicastIpAddressChange@20	proc
					jmp 	_NetioNotifyUnicastIpAddressChange
_NotifyUnicastIpAddressChange@20	endp

					extrn	_NetioCancelMibChangeNotify2:dword

					public 	_CancelMibChangeNotify2@4
_CancelMibChangeNotify2@4 		proc
					jmp 	_NetioCancelMibChangeNotify2
_CancelMibChangeNotify2@4 		endp

					extrn	_NetioFreeMibTable:dword

					public 	_FreeMibTable@4
_FreeMibTable@4 			proc
					jmp 	_NetioFreeMibTable
_FreeMibTable@4 			endp
	
        				end


