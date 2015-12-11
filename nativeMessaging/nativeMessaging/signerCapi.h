#pragma once

#include <map>

#define OPERATION	0
#define THUMBPRINT	1
#define SIGN_TYPE	2
#define SA_B64		3

using namespace System::Security::Cryptography::X509Certificates;
/*
struct cmp_str
{
	bool operator()(char const *a, char const *b)
	{
		return std::strcmp(a, b) < 0;
	}
};
*/

typedef std::map<int, char*> ::iterator it_type;


class signerCapi
{

public:
	signerCapi(void);
	~signerCapi(void);

	
	char* getCertificate(char* title,
		char* msg, char* subjectRegex, char* issuerRegex);
	char* sign(int hashAlg, char* saValue, char* thumbprint);
	int getKeySize();
	char* getSubject(void);

	void signerCapi::printToStdOut(char *);
	char * signerCapi::ReadFromStdIn(void);

	void signerCapi::getCertificateStdOut(char * certb64, char* thumbprint, 
		char* subject, int keySize);

	char*  signerCapi::getThumbprint();
	std::map<int, char*> signerCapi::parseJson(char* original);
	char* signerCapi::convert(System::String^ src);
	System::String^  signerCapi::clean(System::String^ src);

	void signerCapi::getCertificate(const char* thumnprint);
	void signerCapi::getKeySizeStdOut(int keySize);

	void signerCapi::printMessageStdOut(const char * content);
	int signerCapi::keyToInt(char* key);
	void signerCapi::getSubjectStdOut(char * subject);
	void signerCapi::signStdOut(char * sign);

	void signerCapi::isActiveStdOut();


};

