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
static std::string IVStr = "ABCDEF0123456789";

SecByteBlock GetKey()
{
	SecByteBlock key(AES::MAX_KEYLENGTH);
	memset(key, 0x30, key.size());
	KeyStr.size() <= AES::MAX_KEYLENGTH
		? memcpy(key, KeyStr.c_str(), KeyStr.size())
		: memcpy(key, KeyStr.c_str(), AES::MAX_KEYLENGTH);
	return key;
}
SecByteBlock GetIV()
{
	SecByteBlock IV(AES::BLOCKSIZE);
	memset(IV, 0x30, IV.size());
	KeyStr.size() <= AES::BLOCKSIZE
        ? memcpy(IV, IVStr.c_str(), IVStr.size())
        : memcpy(IV, IVStr.c_str(), AES::BLOCKSIZE);
	return IV;
}
#pragma region ECB
FString ECB_EnCrypto(string inPlain)
{
	string cipher; //存密文
	string cipherOut; //存输出的string密文
	SecByteBlock Key = GetKey();
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

FString ECB_DeCrypto(string inCipher)
{
	string plain; //存明文
	string plainOut; //存输出的string明文
	//既然加密后有对密文Encoder，那我们也一样要对密文先进行Decoder
	StringSource(inCipher, true,
	             new HexDecoder(new StringSink(plain)
	             )
	);
	ECB_Mode<AES>::Decryption d;
	SecByteBlock Key = GetKey();
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
#pragma endregion
#pragma region CBC
FString CBC_EnCrypto(string inPlain)
{
	string cipher; //存密文
	string cipherOut; //存输出的string密文
	SecByteBlock Key = GetKey();
	CBC_Mode<AES>::Encryption e;
	e.SetKeyWithIV((byte*)Key, AES::MAX_KEYLENGTH,GetIV());
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
FString CBC_DeCrypto(string inCipher)
{
	string plain; //存明文
	string plainOut; //存输出的string明文
	//既然加密后有对密文Encoder，那我们也一样要对密文先进行Decoder
	StringSource(inCipher, true,
                 new HexDecoder(new StringSink(plain)
                 )
    );
	CBC_Mode<AES>::Decryption d;
	SecByteBlock Key = GetKey();
	d.SetKeyWithIV((byte*)Key, AES::MAX_KEYLENGTH,GetIV());
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
#pragma endregion
#pragma region CFB
FString CFB_EnCrypto(string inPlain)
{
	string cipher; //存密文
	string cipherOut; //存输出的string密文
	SecByteBlock Key = GetKey();
	CFB_Mode<AES>::Encryption e;
	e.SetKeyWithIV((byte*)Key, AES::MAX_KEYLENGTH,GetIV());
	//这一步StingSource是将明文通过 encryption进行加密，得到cipher密文
	StringSource(inPlain, true,
                 new StreamTransformationFilter(e,
                                                new StringSink(cipher)
                                                , BlockPaddingSchemeDef::NO_PADDING
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
FString CFB_DeCrypto(string inCipher)
{
	string plain; //存明文
	string plainOut; //存输出的string明文
	//既然加密后有对密文Encoder，那我们也一样要对密文先进行Decoder
	StringSource(inCipher, true,
                 new HexDecoder(new StringSink(plain)
                 )
    );
	CFB_Mode<AES>::Decryption d;
	SecByteBlock Key = GetKey();
	d.SetKeyWithIV((byte*)Key, AES::MAX_KEYLENGTH,GetIV());
	StringSource s(plain, true,
                   new StreamTransformationFilter(d,
                                                  new StringSink(plainOut)
                                                  , BlockPaddingSchemeDef::NO_PADDING
                                                  , true
                   )
    );
	UE_LOG(LogTemp, Warning, TEXT(" the recovered:%s"), UTF8_TO_TCHAR(plainOut.c_str()));
	return UTF8_TO_TCHAR(plainOut.c_str());
}
#pragma endregion
#pragma region OFB
FString OFB_EnCrypto(string inPlain)
{
	string cipher; //存密文
	string cipherOut; //存输出的string密文
	SecByteBlock Key = GetKey();
	OFB_Mode<AES>::Encryption e;
	e.SetKeyWithIV((byte*)Key, AES::MAX_KEYLENGTH,GetIV());
	//这一步StingSource是将明文通过 encryption进行加密，得到cipher密文
	StringSource(inPlain, true,
                 new StreamTransformationFilter(e,
                                                new StringSink(cipher)
                                                , BlockPaddingSchemeDef::NO_PADDING
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
FString OFB_DeCrypto(string inCipher)
{
	string plain; //存明文
	string plainOut; //存输出的string明文
	//既然加密后有对密文Encoder，那我们也一样要对密文先进行Decoder
	StringSource(inCipher, true,
                 new HexDecoder(new StringSink(plain)
                 )
    );
	OFB_Mode<AES>::Decryption d;
	SecByteBlock Key = GetKey();
	d.SetKeyWithIV((byte*)Key, AES::MAX_KEYLENGTH,GetIV());
	StringSource s(plain, true,
                   new StreamTransformationFilter(d,
                                                  new StringSink(plainOut)
                                                  , BlockPaddingSchemeDef::NO_PADDING
                                                  , true
                   )
    );
	UE_LOG(LogTemp, Warning, TEXT(" the recovered:%s"), UTF8_TO_TCHAR(plainOut.c_str()));
	return UTF8_TO_TCHAR(plainOut.c_str());
}
#pragma endregion
#pragma region CTR
FString CTR_EnCrypto(string inPlain)
{
	string cipher; //存密文
	string cipherOut; //存输出的string密文
	SecByteBlock Key = GetKey();
	CTR_Mode<AES>::Encryption e;
	e.SetKeyWithIV((byte*)Key, AES::MAX_KEYLENGTH,GetIV());
	//这一步StingSource是将明文通过 encryption进行加密，得到cipher密文
	StringSource(inPlain, true,
                 new StreamTransformationFilter(e,
                                                new StringSink(cipher)
                                                , BlockPaddingSchemeDef::NO_PADDING
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
FString CTR_DeCrypto(string inCipher)
{
	string plain; //存明文
	string plainOut; //存输出的string明文
	//既然加密后有对密文Encoder，那我们也一样要对密文先进行Decoder
	StringSource(inCipher, true,
                 new HexDecoder(new StringSink(plain)
                 )
    );
	CTR_Mode<AES>::Decryption d;
	SecByteBlock Key = GetKey();
	d.SetKeyWithIV((byte*)Key, AES::MAX_KEYLENGTH,GetIV());
	StringSource s(plain, true,
                   new StreamTransformationFilter(d,
                                                  new StringSink(plainOut)
                                                  , BlockPaddingSchemeDef::NO_PADDING
                                                  , true
                   )
    );
	UE_LOG(LogTemp, Warning, TEXT(" the recovered:%s"), UTF8_TO_TCHAR(plainOut.c_str()));
	return UTF8_TO_TCHAR(plainOut.c_str());
}
#pragma endregion 
FString UTBBCryptBPLibrary::AESFunctionLib(FString inString, ECryptMode mode, ECryActionType action)
{
	FString OutString = "";
	const string InStringTarget = TCHAR_TO_UTF8(*inString);
	switch (action)
	{
	case ECryActionType::Encrypt:
		switch (mode)
		{
		case ECryptMode::ECB:
			OutString = ECB_EnCrypto(InStringTarget);
			break;
		case ECryptMode::CBC:
			OutString = CBC_EnCrypto(InStringTarget);
			break;
		case ECryptMode::CFB:
			OutString = CFB_EnCrypto(InStringTarget);
			break;
		case ECryptMode::OFB:
			OutString = OFB_EnCrypto(InStringTarget);
			break;
		case ECryptMode::CTR:
			OutString = CTR_EnCrypto(InStringTarget);
			break;
		default:
			break;
		}
		break;
	case ECryActionType::Decrypt:
		switch (mode)
		{
		case ECryptMode::ECB:
			OutString = ECB_DeCrypto(InStringTarget);
			break;
		case ECryptMode::CBC:
			OutString = CBC_DeCrypto(InStringTarget);
			break;
		case ECryptMode::CFB:
			OutString = CFB_DeCrypto(InStringTarget);
			break;
		case ECryptMode::OFB:
			OutString = OFB_DeCrypto(InStringTarget);
			break;
		case ECryptMode::CTR:
			OutString = CTR_DeCrypto(InStringTarget);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}
	return OutString;
}
