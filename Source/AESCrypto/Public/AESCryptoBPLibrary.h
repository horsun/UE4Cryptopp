// Copyright 1998-2019 Epic Games, Inc. All Rights Reserved.

#pragma once
#include <string>
using namespace std;

enum  ECryptMode 
{
	ECB=0,
	CBC,
	CFB,
	OFB,
	CTR
};

enum  ECryptPadding 
{
	NO_PADDING=0,

	ZEROS_PADDING,

	PKCS_PADDING,

	ONE_AND_ZEROS_PADDING,

	W3C_PADDING,

	DEFAULT_PADDING
};

enum  ECryActionType 
{
	Encrypt=0,
	Decrypt,
};
class AESCRYPTO_API AESFunctionClass
{
public:
	AESFunctionClass() {};
	~AESFunctionClass() {};
	static string AESFunctionLib(string inString, ECryptMode mode, ECryActionType action, ECryptPadding padding);
	static bool AESFileDecrypto(FString Path, FString FileName);
	static bool AESFileEncrypto(FString Path, FString FileName);
	static bool MediaDecrypto(FString Path, TArray<uint8>& OutPut);
};
