// Fill out your copyright notice in the Description page of Project Settings.


#include "UECryptoBPFunctionLib.h"
#include <string>
#include "Serialization/ArrayReader.h"
using namespace std;

FString UUECryptoBPFunctionLib::UEAESCryptoFunction(FString inString, ECryptMode_UE mode, ECryActionType_UE action, ECryptPadding_UE padding)
{
	const string InStringTarget = TCHAR_TO_UTF8(*inString);
	string outString = AESFunctionClass::AESFunctionLib(InStringTarget,ECryptMode(int(mode)),ECryActionType(int(action)),ECryptPadding(int(padding)));
	return UTF8_TO_TCHAR(outString.c_str());
}

bool UUECryptoBPFunctionLib::AESFileDecryptoFunction(FString Path, FString FileName)
{
	return AESFunctionClass::AESFileDecrypto(Path, FileName);
}

bool UUECryptoBPFunctionLib::AESFileEncryptoFunction(FString Path, FString FileName)
{
	return AESFunctionClass::AESFileEncrypto(Path,FileName);
}

FArchive * UUECryptoBPFunctionLib::MediaDecryptoFunction(FString Path)
{
	FArrayReader *Reader = new FArrayReader();
	if (AESFunctionClass::MediaDecrypto(Path,*Reader))
	{
		return Reader;
	}
	return nullptr;
}
