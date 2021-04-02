// Copyright 1998-2019 Epic Games, Inc. All Rights Reserved.

#include "TBBCryptBPLibrary.h"
#include "aes.h"
#include "hex.h"         // StreamTransformationFilter  
#include "modes.h"	     // CFB_Mode  
#include <iostream>   // std:cerr    
#include <sstream>   // std::stringstream    
#include <string>
#include "channels.h"
#include "mqueue.h"
using namespace std;
using namespace CryptoPP;
#pragma comment(lib, "cryptlib.lib" )

UTBBCryptBPLibrary::UTBBCryptBPLibrary(const FObjectInitializer& ObjectInitializer)
	: Super(ObjectInitializer)
{
}

static std::string KeyStr = "0123456789ABCDEF0123456789ABCDEF";
static const FString IVStr = "ABCDEF0123456789";

SecByteBlock getKey()
{
	SecByteBlock key(AES::MAX_KEYLENGTH);
	memset(key, 0x30, key.size());
	KeyStr.size() <= AES::MAX_KEYLENGTH
		? memcpy(key, KeyStr.c_str(), KeyStr.size())
		: memcpy(key, KeyStr.c_str(), AES::MAX_KEYLENGTH);
	return key;
}

FString EnCrypto(string inPlain)
{
	string cipher; //存密文
	string cipherOut; //存输出的string密文
	SecByteBlock Key = getKey();
	ECB_Mode<AES>::Encryption e;
	e.SetKey((byte*)Key, AES::MAX_KEYLENGTH);
	//这一步StingSource是将明文通过 encryption进行加密，得到cipher密文
	StringSource(inPlain, true,
	             new StreamTransformationFilter(e,
	                                            new StringSink(cipher)
	                                            , BlockPaddingSchemeDef::ONE_AND_ZEROS_PADDING
	                                            , true
	             )
	);
	//这一步是通过StringSource 将cipher 密文转成可以正常打印阅读的 密文，主要关注HexEncoder 
	StringSource(cipher, true,
	             new HexEncoder(
		             new StringSink(cipherOut)
	             )
	);
	UE_LOG(LogTemp, Warning, TEXT(" the cipher:%s"), UTF8_TO_TCHAR( cipherOut.c_str()));
	return UTF8_TO_TCHAR(cipherOut.c_str());
}

FString DeCrypto(string inCipher)
{
	string plain;//存明文
	string plainOut;//存输出的string明文
	//既然加密后有对密文Encoder，那我们也一样要对密文先进行Decoder
	StringSource(inCipher, true,
	             new HexDecoder(new StringSink(plain)
	             )
	);
	ECB_Mode<AES>::Decryption d;
	SecByteBlock Key = getKey();
	d.SetKey((byte*)Key, AES::MAX_KEYLENGTH);
	StringSource s(plain, true,
	               new StreamTransformationFilter(d,
	                                              new StringSink(plainOut)
	                                              , BlockPaddingSchemeDef::ONE_AND_ZEROS_PADDING
	                                              , true
	               ) 
	); 
	UE_LOG(LogTemp, Warning, TEXT(" the recovered:%s"), UTF8_TO_TCHAR(plainOut.c_str()));
	return UTF8_TO_TCHAR(plainOut.c_str());
}

FString UTBBCryptBPLibrary::AESFunctionLib(FString inString, ECryptMode mode, ECryActionType action)
{
	FString OutString = "";
	bool test = false;
	string inString2 = TCHAR_TO_UTF8(*inString);
	switch (action)
	{
	case ECryActionType::Encrypt:
		switch (mode)
		{
		case ECryptMode::ECB:
			OutString = EnCrypto(inString2);
			break;
			//case ECryptMode::CBC:
			//	OutString = CBC_AESEncryptData(inString, aes_key, aes_IV);
			//	break;
			//case ECryptMode::CFB:
			//	OutString = CFB_AESEncryptData(inString, aes_key, aes_IV);
			//	break;
			//case ECryptMode::OFB:
			//	OutString = OFB_AESEncryptData(inString, aes_key, aes_IV);
			//	break;
			//case ECryptMode::CTR:
			//	OutString = CTR_AESEncryptData(inString, aes_key, aes_IV);
			//	break;
		default:
			break;
		}
		break;
	case ECryActionType::Decrypt:
		switch (mode)
		{
		case ECryptMode::ECB:
			OutString = DeCrypto(inString2);
			break;
			/*	case ECryptMode::CBC:
					OutString = CBC_AESDecryptData(inString, aes_key, aes_IV, test);
					break;
				case ECryptMode::CFB:
					OutString = CFB_AESDecryptData(inString, aes_key, aes_IV, test);
					break;
				case ECryptMode::OFB:
					OutString = OFB_AESDecryptData(inString, aes_key, aes_IV, test);
					break;
				case ECryptMode::CTR:
					OutString = CTR_AESDecryptData(inString, aes_key, aes_IV, test);
					break;*/
		default:
			break;
		}
		break;
	default:
		break;
	}
	return OutString;
}
