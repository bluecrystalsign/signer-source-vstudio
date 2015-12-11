// nativeMessaging.cpp : main project file.

#include "stdafx.h"

using namespace System;
#include "signerCapi.h"

		int main(array<System::String ^> ^args)
		{
			signerCapi sign = signerCapi();
			try {
				


				char* inJson = sign.ReadFromStdIn();
				//char* inJson = "{\"operation\":\"sign\",\"thumbprint\":\"3B6D44ADF0BBFF00EFD6276427DCF011B978DB00\",\"sign_type\":2,\"sa_b64\":\"MYIB+DAcBgkqhkiG9w0BCQUxDxcNMTUxMjAyMTg1NzE1WjCBlAYLKoZIhvcNAQkQAg8xgYQwgYEGCGBMAQcBAQIBMC8wCwYJYIZIAWUDBAIBBCDdV8mKQxO8E5jOZUPTgCRYlXz3Fq4ylOxNjCYlEpHmwTBEMEIGCyqGSIb3DQEJEAUBFjNodHRwOi8vcG9saXRpY2FzLmljcGJyYXNpbC5nb3YuYnIvUEFfQURfUkJfdjJfMS5kZXIwgfUGCyqGSIb3DQEJEAIvMYHlMIHiMIHfMIHcBCCwYEUeTbg/lemacOmYh9eaBFm/SJH0zvvyGjuFMhdimzCBtzCBoaSBnjCBmzELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxQTA/BgNVBAMTOENPTU9ETyBTSEEtMjU2IENsaWVudCBBdXRoZW50aWNhdGlvbiBhbmQgU2VjdXJlIEVtYWlsIENBAhEAtIobX+vA5SqUhPODdUlNEzAvBgkqhkiG9w0BCQQxIgQgKHGdMaCCt021jz8m+iWZZs8FaDPc9qipzV3LW1H8DOMwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHAQ==\"}";

				std::map<int, char*>  appMap = sign.parseJson(inJson);
				//std::map<int, char*>  appMap;
				const char * op = appMap[OPERATION];
				//const char * op = "getCertificate";
				const char * opRef[] = { "getCertificate", "getKeySize", "getSubject", "sign", "isActive" };

				if (strcmp(op, opRef[0]) == 0){
					char * cert = sign.getCertificate("", "", "", "");
					char * thumbrpint = sign.getThumbprint();
					char * subject = sign.getSubject();
					int keySize = sign.getKeySize();

					sign.getCertificateStdOut(cert, thumbrpint, subject, keySize);
				} else if (strcmp(op, opRef[1]) == 0){
					char*  thumbprint = ".";
					thumbprint =  appMap[THUMBPRINT];
					String^ thumbprintStr = gcnew  String(thumbprint);
					sign.getCertificate(thumbprint);
					int ks = sign.getKeySize();
					sign.getKeySizeStdOut(ks);

				} else if (strcmp(op, opRef[2]) == 0){

					char*  thumbprint = ".";
					thumbprint = appMap[THUMBPRINT];
					String^ thumbprintStr = gcnew  String(thumbprint);
					sign.getCertificate(thumbprint);
					char* subject = sign.getSubject();
					sign.getSubjectStdOut(subject);
				}
				else if (strcmp(op, opRef[3]) == 0){

					char*  thumbprint = appMap[THUMBPRINT];
					
					char*  signType = appMap[SIGN_TYPE];
					char*  saB64 = appMap[SA_B64];

				//	sign.getCertificate(thumbprint);
					char* signResult = sign.sign(atoi(signType), saB64, thumbprint);
					sign.signStdOut(signResult);
				}
				else if (strcmp(op, opRef[4]) == 0){
					sign.isActiveStdOut();
				}

				else
				{
					char* jsonOut = "{\"status\":\"1\",\"message\":\"operation not permited\"}";

					sign.printToStdOut(jsonOut);
				}
			}
			catch (...){
				char* jsonOut = "{\"status\":\"2\",\"message\":\"exception\"}";
				sign.printToStdOut(jsonOut);
			}


				
			return 0;
		}


