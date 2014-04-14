        			page    ,132
        			title   Netio Redirections

        			.code
	
				extrn	NetioGetUnicastIpAddressTable:qword
	
        			public GetUnicastIpAddressTable
GetUnicastIpAddressTable	proc
				jmp 	NetioGetUnicastIpAddressTable
GetUnicastIpAddressTable	endp

				extrn	NetioNotifyUnicastIpAddressChange:qword

				public 	NotifyUnicastIpAddressChange
NotifyUnicastIpAddressChange	proc
				jmp 	NetioNotifyUnicastIpAddressChange
NotifyUnicastIpAddressChange	endp

				extrn	NetioCancelMibChangeNotify2:qword

				public 	CancelMibChangeNotify2
CancelMibChangeNotify2 		proc
				jmp 	NetioCancelMibChangeNotify2
CancelMibChangeNotify2 		endp

				extrn	NetioFreeMibTable:qword
	
				public 	FreeMibTable
FreeMibTable 			proc
				jmp 	NetioFreeMibTable
FreeMibTable 			endp
	
        				end


