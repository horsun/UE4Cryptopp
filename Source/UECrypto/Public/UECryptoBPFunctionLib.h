// Fill out your copyright notice in the Description page of Project Settings.

#pragma once

#include "CoreMinimal.h"
#include "Kismet/BlueprintFunctionLibrary.h"
#include "AESCrypto/Public/AESCryptoBPLibrary.h"
#include "UECryptoBPFunctionLib.generated.h"

/**
 *
 */
UENUM(BlueprintType)
enum class ECryptMode_UE : uint8
{
	ECB=0,
	CBC,
	CFB,
	OFB,
	CTR
};

UENUM(BlueprintType)
enum class ECryptPadding_UE : uint8
{
	NO_PADDING=0,

	ZEROS_PADDING,

	PKCS_PADDING,

	ONE_AND_ZEROS_PADDING,

	W3C_PADDING,

	DEFAULT_PADDING
};

UENUM(BlueprintType)
enum class ECryActionType_UE : uint8
{
	Encrypt=0,
	Decrypt,
};

UCLASS()
class UECRYPTO_API UUECryptoBPFunctionLib : public UBlueprintFunctionLibrary
{
	GENERATED_BODY()
public:
	friend class AESFunctionClass;

	UFUNCTION(BlueprintCallable)
		static FString UEAESCryptoFunction(FString inString, ECryptMode_UE mode, ECryActionType_UE action, ECryptPadding_UE padding);
	//UFUNCTION(BlueprintCallable)
	//static bool AESFileDecrypto(FString Path, FString FileName);
	//UFUNCTION(BlueprintCallable)
	//static bool AESFileEncrypto(FString Path, FString FileName);
	//static FArchive* MediaDecrypto(FString Path);
};
