// Fill out your copyright notice in the Description page of Project Settings.


#include "UECryptoBPFunctionLib.h"
#include <string>
using namespace std;

FString UUECryptoBPFunctionLib::UEAESCryptoFunction(FString inString, ECryptMode_UE mode, ECryActionType_UE action, ECryptPadding_UE padding)
{
	const string InStringTarget = TCHAR_TO_UTF8(*inString);
	string outString = AESFunctionClass::AESFunctionLib(InStringTarget,ECryptMode(int(mode)),ECryActionType(int(action)),ECryptPadding(int(padding)));
	return UTF8_TO_TCHAR(outString.c_str());
}