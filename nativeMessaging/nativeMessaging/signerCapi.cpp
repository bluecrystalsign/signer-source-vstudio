#include "stdafx.h"

#include "signerCapi.h"
#include <stdio.h>
#include <string.h>
#include <vcclr.h >
#include <stdlib.h >
#include <fcntl.h>
#include <iostream>
#include <io.h>

#include <map>

#using <System.dll>
#using <System.Security.dll>

#include <msclr\marshal_cppstd.h>

using namespace System;
using namespace System::Security::Cryptography;
using namespace System::Security::Cryptography::X509Certificates;
using namespace System::Security::Cryptography::Pkcs;
using namespace System::IO;
using namespace System::Text::RegularExpressions;

using namespace std;
using namespace ittru;


gcroot <X509Certificate2 ^>  certificate;
gcroot <signAx ^> signer;


signerCapi::signerCapi(void)
{
	signer = gcnew signAx();
}


signerCapi::~signerCapi(void)
{
}

void signerCapi::printMessageStdOut(const char * content){
	String^ contentStr = gcnew  String(content);
	String^ jsonOut = "{"
		+ "\"status\":\"0\","
		+ "\"message\":\"" + contentStr + "\""
		+ "}";
		printToStdOut(convert (jsonOut));

}
void signerCapi::printToStdOut(char * content){

	_setmode(_fileno(stdout), _O_BINARY);

	std::string strOut(content);
			int uiSize = strOut.length();

			std::cout << char(((uiSize >> 0) & 0xFF));
			std::cout << char(((uiSize >> 8) & 0xFF));
			std::cout << char(((uiSize >> 16) & 0xFF));
			std::cout << char(((uiSize >> 24) & 0xFF));
			std::cout << strOut.c_str();
}

std::map<int, char*> signerCapi::parseJson(char* original){
	std::map<int, char*> ret;

	String^ originalStr = gcnew String(original);
	String^ delimStr = ",";
	array<Char>^ delimiter = delimStr->ToCharArray();
	array<String^>^ strArr = originalStr->Split(delimiter);

	delimStr = ":";
	delimiter = delimStr->ToCharArray();

	for (int word = 0; word < strArr->Length; word++){
		array<String^>^ strArr2 = strArr[word]->Split(delimiter);
		char * key = convert(clean(strArr2[0]));
		ret[ keyToInt(key) ] = convert(clean(strArr2[1]));
	}

	return ret;
}

int signerCapi::keyToInt(char* key){
	if (strcmp(key, "operation") == 0){
		return OPERATION;
	}
	else if (strcmp(key, "thumbprint") == 0){
		return THUMBPRINT;
	}
	else if (strcmp(key, "sign_type") == 0){
		return SIGN_TYPE;
	}
	else if (strcmp(key, "sa_b64") == 0){
		return SA_B64;
	}
	else {
		return -1;
	}
}



char * signerCapi::ReadFromStdIn(void){

	_setmode(_fileno(stdin), _O_BINARY);

	char cBuffer[65536] = { 0 };

	unsigned int uiSize = 0;
	std::cin.read((char*)&uiSize, sizeof(unsigned int));

		memset(cBuffer, 0, 65536);
		std::cin.read(cBuffer, uiSize);

		std::string strIn(cBuffer);

		return cBuffer;
}

String^  signerCapi::clean(String^ src){
	String ^delim = gcnew String(" {}\"\\");
	src = src->TrimStart(delim->ToCharArray());
	src = src->TrimEnd(delim->ToCharArray());

	return src;

}

char* signerCapi::convert(String^ src){



	pin_ptr<const wchar_t> wch = PtrToStringChars(src);

	size_t convertedChars = 0;
	size_t  sizeInBytes = ((src->Length + 1) * 2);
	errno_t err = 0;
	char* ret = (char *)malloc(sizeInBytes);

	err = wcstombs_s(&convertedChars,
		ret, sizeInBytes,
		wch, sizeInBytes);
	return ret;

}

void signerCapi::getCertificateStdOut(char * certb64, char* thumbprint, 
	char*subject, int keySize){
	String^ certb64Str = gcnew  String(certb64);
	String^ thumbprintStr = gcnew  String(thumbprint);
	String^ subjectStr = gcnew  String(subject);

	String^ jsonOut = "{"
		+ "\"status\":\"0\","
		+ "\"message\":\"OK\","
		+ "\"thumbprint\":\"" + thumbprintStr + "\","
		+ "\"certb64\":\"" + certb64Str + "\","
		+ "\"subject\":\"" + subjectStr + "\","
		+ "\"keySize\":\"" + keySize + "\""
		+ "}";
	printToStdOut(convert(jsonOut));
}

void signerCapi::getSubjectStdOut(char * subject){
	String^ subjectStr = gcnew  String(subject);

	String^ jsonOut = "{"
		+ "\"status\":\"0\","
		+ "\"message\":\"OK\","
		+ "\"subject\":\"" + subjectStr + "\""
		+ "}";
	printToStdOut(convert(jsonOut));
}

void signerCapi::signStdOut(char * sign){
	String^ signStr = gcnew  String(sign);

	String^ jsonOut = "{"
		+ "\"status\":\"0\","
		+ "\"message\":\"OK\","
		+ "\"sign\":\"" + signStr + "\""
		+ "}";
	printToStdOut(convert(jsonOut));
}

void signerCapi::isActiveStdOut(){

	String^ jsonOut = "{"
		+ "\"status\":\"0\","
		+ "\"message\":\"OK\""
		+ "}";
	printToStdOut(convert(jsonOut));
}

void signerCapi::getKeySizeStdOut(int keySize){
	String^ ksSize = Convert::ToString(keySize);

	String^ jsonOut = "{"
		+ "\"status\":\"0\","
		+ "\"message\":\"OK\","
		+ "\"keySize\":\"" + ksSize + "\""
		+ "}";
	printToStdOut(convert(jsonOut));
}




void signerCapi::getCertificate(const char* thumnprint){
	signer->getCertificateByThumbprint(gcnew String(thumnprint));
}

char* signerCapi::getCertificate(char* title,
char* msg, char* subjectRegex, char* issuerRegex){
	return convert(signer->getCertificate(gcnew String(title), gcnew String(msg),
		gcnew String(subjectRegex), gcnew String(issuerRegex)));
}

char* signerCapi::sign(int hashAlg, char* saValue, char* thumbprint){
	String^ thumbprintStr = gcnew  String(thumbprint);
	signer->selectCertificateByThumbprint(thumbprintStr);
	return convert( signer->sign(hashAlg, gcnew String(saValue)) );
}


int signerCapi::getKeySize(){
	return ( signer->getKeySize() );
}

char*  signerCapi::getThumbprint(){
	return convert ( signer->getThumbprint() );
}

char* signerCapi::getSubject(void){
	return convert( signer->getSubject() );
}



/*
void signerCapi::getCertificateStdOut(char * certb64, char* thumbprint){

	_setmode(_fileno(stdout), _O_BINARY);

	String^ certb64Str = gcnew  String(certb64);
	String^ thumbprintStr = gcnew  String(thumbprint);

	String^ jsonOut =	"{"
						+ "\"status\":\"0\","
						+ "\"message\":\"OK\","
						+ "\"thumbprint\":\"" + thumbprintStr + "\","
						+ "\"certb64\":\"" + certb64Str + "\""
						+ "}";

	msclr::interop::marshal_context context;

	std::string strOut = context.marshal_as<std::string>(jsonOut);
	int uiSize = strOut.length();

	std::cout << char(((uiSize >> 0) & 0xFF));
	std::cout << char(((uiSize >> 8) & 0xFF));
	std::cout << char(((uiSize >> 16) & 0xFF));
	std::cout << char(((uiSize >> 24) & 0xFF));
	std::cout << strOut.c_str();

}
*/
