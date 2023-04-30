#include <Windows.h>
#include <wincrypt.h>
#include <fstream>
#include <string>
#include <iostream>

#pragma comment (lib, "Crypt32.lib")

void writePubKeyAtTheEnd(char* pubName, char* execName) {
	std::ifstream pubfile(pubName, std::ios::binary);
	std::ofstream exe(execName, std::ios::binary | std::ios::app);
	if (!exe || !pubfile)
	{
		std::cerr << "Impossible d'ouvrir les fichiers\n";
	}

	std::copy(std::istreambuf_iterator<char>(pubfile),
		std::istreambuf_iterator<char>(),
		std::ostreambuf_iterator<char>(exe));

	// Fermeture des fichiers
	pubfile.close();
	exe.close();
}


int main(int argc, char* argv[]) {

	writePubKeyAtTheEnd(argv[1], argv[2]);
	return 0;
}