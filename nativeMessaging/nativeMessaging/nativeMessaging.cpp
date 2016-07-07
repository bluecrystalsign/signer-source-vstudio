// nativeMessaging.cpp : main project file.

#include "stdafx.h"

using namespace System;
#include "signerCapi.h"

		int main(array<System::String ^> ^args)
		{
			signerCapi sign = signerCapi();
			try {
				/* rotina de testes para prequiçosos!
				char * cert = sign.getCertificate("", "", "", "");
				char * thumbrpint = sign.getThumbprint();
				char * subject = sign.getSubject();
				int keySize = sign.getKeySize();
				sign.getCertificateStdOut(cert, thumbrpint, subject, keySize);

				char* signResult = sign.sign(2, 
					"MYIBqzAcBgkqhkiG9w0BCQUxDxcNMTYwNjI0MTIyNTQxWjCBlAYLKoZIhvcNAQkQAg8xgYQwgYEGCGBMAQcBAQIBMC8wCwYJYIZIAWUDBAIBBCDdV8mKQxO8E5jOZUPTgCRYlXz3Fq4ylOxNjCYlEpHmwTBEMEIGCyqGSIb3DQEJEAUBFjNodHRwOi8vcG9saXRpY2FzLmljcGJyYXNpbC5nb3YuYnIvUEFfQURfUkJfdjJfMS5kZXIwgagGCyqGSIb3DQEJEAIvMYGYMIGVMIGSMIGPBCAEOJH1iLiclMLGoGvr6N/90CxfzAGsMz/eGG5A29xE0jBrMF2kWzBZMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxEzARBgoJkiaJk/IsZAEZFgNybnAxKzApBgNVBAMTIlJlZGUgTmFjaW9uYWwgZGUgRW5zaW5vIGUgUGVzcXVpc2ECCko9ny4AAQAADQMwLwYJKoZIhvcNAQkEMSIEIHHIK69uLYZh22xEaGgL1TtWl4E2swKeWM723c4gNFtMMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwE=",
					thumbrpint);

				exit(0);
				*/


				char* inJson = sign.ReadFromStdIn();

				std::map<int, char*>  appMap = sign.parseJson(inJson);
				const char * op = appMap[OPERATION];
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
			catch (Exception^ e){
				String^ messageEx = e->Message;
				char* messageCharP = sign.convert(messageEx);
				std::string str1("{\"status\":\"2\",\"message\":\"");
				std::string str2(messageCharP);
				std::string str3("\"}");
				//				char* jsonOut = "{\"status\":\"2\",\"message\":\""+messageEx->ToCharArray+"\"}";
				std::string jsonOut =  str1+ str2 + str3;
				char *cstr = new char[jsonOut.length() + 1];
				strcpy(cstr, jsonOut.c_str());
				sign.printToStdOut(cstr);
			}


				
			return 0;
		}

