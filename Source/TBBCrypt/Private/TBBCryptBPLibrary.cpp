// Copyright 1998-2019 Epic Games, Inc. All Rights Reserved.

#include "TBBCryptBPLibrary.h"
#include "TBBCrypt.h"
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


FString ECB_AESEncryptData(FString aes_content, FString aes_key)
{

	//std::string sKey = "0123456789ABCDEF0123456789ABCDEF";
	std::string sKey = TCHAR_TO_UTF8(*aes_key);
	const char * plainText = TCHAR_TO_UTF8(*aes_content);
	std::string outstr;


	//填key    
	SecByteBlock key(AES::MAX_KEYLENGTH);
	memset(key, 0x30, key.size());
	sKey.size() <= AES::MAX_KEYLENGTH ? memcpy(key, sKey.c_str(), sKey.size()) : memcpy(key, sKey.c_str(), AES::MAX_KEYLENGTH);


	AES::Encryption aesEncryption((byte *)key, AES::MAX_KEYLENGTH);

	ECB_Mode_ExternalCipher::Encryption ecbEncryption(aesEncryption);
	StreamTransformationFilter*ecbEncryptor =  new StreamTransformationFilter (
		ecbEncryption,
		new HexEncoder( new StringSink(outstr)),
		BlockPaddingSchemeDef::BlockPaddingScheme::DEFAULT_PADDING,
		true
	);
	ecbEncryptor->Put((byte *)plainText, strlen(plainText));
	ecbEncryptor->MessageEnd();

	return UTF8_TO_TCHAR(outstr.c_str());

}


FString  ECB_AESDecryptData(FString aes_content, FString aes_key, bool & result)
{

	std::string sKey = TCHAR_TO_UTF8(*aes_key);
	const char *cipherText = TCHAR_TO_UTF8(*aes_content);
	std::string outstr;
	try
	{
		//填key    
		SecByteBlock key(AES::MAX_KEYLENGTH);
		memset(key, 0x30, key.size());
		sKey.size() <= AES::MAX_KEYLENGTH ? memcpy(key, sKey.c_str(), sKey.size()) : memcpy(key, sKey.c_str(), AES::MAX_KEYLENGTH);

		ECB_Mode<AES >::Decryption ecbDecryption((byte *)key, AES::MAX_KEYLENGTH);

		HexDecoder decryptor(new StreamTransformationFilter(ecbDecryption, new StringSink(outstr), BlockPaddingSchemeDef::BlockPaddingScheme::DEFAULT_PADDING,
			true
		));
		decryptor.Put((byte *)cipherText, strlen(cipherText));
		decryptor.MessageEnd();
		result = true;
	}
	catch (const std::exception& e)
	{
		outstr = "error";
		UE_LOG(LogTemp, Error, TEXT("ECB_AESDecryptData failed! error :%s"),e.what());
		result = false;
	}
	return UTF8_TO_TCHAR(outstr.c_str());
}

#pragma endregion

#pragma region CBC


FString  CBC_AESEncryptData(FString aes_content, FString aes_key, FString aes_IV)
{
	//std::string sKey = "0123456789ABCDEF0123456789ABCDEF";
	std::string sKey = TCHAR_TO_UTF8(*aes_key);
	std::string sIV = TCHAR_TO_UTF8(*aes_IV);
	const char *plainText = TCHAR_TO_UTF8(*aes_content);
	std::string outstr;

	//填key    
	SecByteBlock key(AES::MAX_KEYLENGTH);
	memset(key, 0x30, key.size());
	sKey.size() <= AES::MAX_KEYLENGTH ? memcpy(key, sKey.c_str(), sKey.size()) : memcpy(key, sKey.c_str(), AES::MAX_KEYLENGTH);

	//填iv    
	byte iv[AES::BLOCKSIZE];
	memset(iv, 0x30, AES::BLOCKSIZE);
	sIV.size() <= AES::BLOCKSIZE ? memcpy(iv, sIV.c_str(), sIV.size()) : memcpy(iv, sIV.c_str(), AES::BLOCKSIZE);

	AES::Encryption aesEncryption((byte *)key, AES::MAX_KEYLENGTH);

	CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

	StreamTransformationFilter cbcEncryptor(cbcEncryption, new HexEncoder(new StringSink(outstr)), BlockPaddingSchemeDef::BlockPaddingScheme::ONE_AND_ZEROS_PADDING,
		true);
	cbcEncryptor.Put((byte *)plainText, strlen(plainText));
	cbcEncryptor.MessageEnd();

	return UTF8_TO_TCHAR(outstr.c_str());
}

FString  CBC_AESDecryptData(FString aes_content, FString aes_key, FString aes_IV, bool & result)
{
	std::string sKey = TCHAR_TO_UTF8(*aes_key);
	std::string sIV = TCHAR_TO_UTF8(*aes_IV);
	const char *cipherText = TCHAR_TO_UTF8(*aes_content);
	std::string outstr;

	try
	{
		//填key    
		SecByteBlock key(AES::MAX_KEYLENGTH);
		memset(key, 0x30, key.size());
		sKey.size() <= AES::MAX_KEYLENGTH ? memcpy(key, sKey.c_str(), sKey.size()) : memcpy(key, sKey.c_str(), AES::MAX_KEYLENGTH);

		//填iv    
		byte iv[AES::BLOCKSIZE];
		memset(iv, 0x30, AES::BLOCKSIZE);
		sIV.size() <= AES::BLOCKSIZE ? memcpy(iv, sIV.c_str(), sIV.size()) : memcpy(iv, sIV.c_str(), AES::BLOCKSIZE);


		CBC_Mode<AES >::Decryption cbcDecryption((byte *)key, AES::MAX_KEYLENGTH, iv);

		HexDecoder decryptor(new StreamTransformationFilter(cbcDecryption, new StringSink(outstr), BlockPaddingSchemeDef::BlockPaddingScheme::ONE_AND_ZEROS_PADDING,
			true));
		decryptor.Put((byte *)cipherText, strlen(cipherText));
		decryptor.MessageEnd();

		result = true;
	}
	catch (const std::exception&)
	{
		outstr = "error";
		UE_LOG(LogTemp, Error, TEXT("CBC_AESDecryptData failed!"));
		result = false;
	}

	return UTF8_TO_TCHAR(outstr.c_str());

}
#pragma endregion

#pragma region CBC_CTS


FString  CBC_CTS_AESEncryptData(FString aes_content, FString aes_key, FString aes_IV)
{
	//std::string sKey = "0123456789ABCDEF0123456789ABCDEF";
	std::string sKey = TCHAR_TO_UTF8(*aes_key);
	std::string sIV = TCHAR_TO_UTF8(*aes_IV);
	const char *plainText = TCHAR_TO_UTF8(*aes_content);
	std::string outstr;

	//填key    
	SecByteBlock key(AES::MAX_KEYLENGTH);
	memset(key, 0x30, key.size());
	sKey.size() <= AES::MAX_KEYLENGTH ? memcpy(key, sKey.c_str(), sKey.size()) : memcpy(key, sKey.c_str(), AES::MAX_KEYLENGTH);

	//填iv    
	byte iv[AES::BLOCKSIZE];
	memset(iv, 0x30, AES::BLOCKSIZE);
	sIV.size() <= AES::BLOCKSIZE ? memcpy(iv, sIV.c_str(), sIV.size()) : memcpy(iv, sIV.c_str(), AES::BLOCKSIZE);

	AES::Encryption aesEncryption((byte *)key, AES::MAX_KEYLENGTH);

	CBC_CTS_Mode_ExternalCipher::Encryption cbcctsEncryption(aesEncryption, iv);

	StreamTransformationFilter cbcctsEncryptor(cbcctsEncryption, new HexEncoder(new StringSink(outstr)), BlockPaddingSchemeDef::BlockPaddingScheme::NO_PADDING,
		true);
	cbcctsEncryptor.Put((byte *)plainText, strlen(plainText));
	cbcctsEncryptor.MessageEnd();

	return UTF8_TO_TCHAR(outstr.c_str());
}

FString  CBC_CTS_AESDecryptData(FString aes_content, FString aes_key, FString aes_IV, bool & result)
{
	std::string sKey = TCHAR_TO_UTF8(*aes_key);
	std::string sIV = TCHAR_TO_UTF8(*aes_IV);
	const char *cipherText = TCHAR_TO_UTF8(*aes_content);
	std::string outstr;

	try
	{
		//填key    
		SecByteBlock key(AES::MAX_KEYLENGTH);
		memset(key, 0x30, key.size());
		sKey.size() <= AES::MAX_KEYLENGTH ? memcpy(key, sKey.c_str(), sKey.size()) : memcpy(key, sKey.c_str(), AES::MAX_KEYLENGTH);

		//填iv    
		byte iv[AES::BLOCKSIZE];
		memset(iv, 0x30, AES::BLOCKSIZE);
		sIV.size() <= AES::BLOCKSIZE ? memcpy(iv, sIV.c_str(), sIV.size()) : memcpy(iv, sIV.c_str(), AES::BLOCKSIZE);


		CBC_CTS_Mode<AES >::Decryption cbcctsDecryption((byte *)key, AES::MAX_KEYLENGTH, iv);

		HexDecoder decryptor(new StreamTransformationFilter(cbcctsDecryption, new StringSink(outstr), BlockPaddingSchemeDef::BlockPaddingScheme::NO_PADDING,
			true));
		decryptor.Put((byte *)cipherText, strlen(cipherText));
		decryptor.MessageEnd();

		result = true;
	}
	catch (const std::exception&)
	{
		outstr = "error";
		UE_LOG(LogTemp, Error, TEXT("CBC_CTS_AESDecryptData failed!"));
		result = false;
	}
	return UTF8_TO_TCHAR(outstr.c_str());
}
#pragma endregion

#pragma region CFB

FString  CFB_AESEncryptData(FString aes_content, FString aes_key, FString aes_IV)
{
	//std::string sKey = "0123456789ABCDEF0123456789ABCDEF";
	std::string sKey = TCHAR_TO_UTF8(*aes_key);
	std::string sIV = TCHAR_TO_UTF8(*aes_IV);
	const char *plainText = TCHAR_TO_UTF8(*aes_content);
	std::string outstr;

	//填key    
	SecByteBlock key(AES::MAX_KEYLENGTH);
	memset(key, 0x30, key.size());
	sKey.size() <= AES::MAX_KEYLENGTH ? memcpy(key, sKey.c_str(), sKey.size()) : memcpy(key, sKey.c_str(), AES::MAX_KEYLENGTH);

	//填iv    
	byte iv[AES::BLOCKSIZE];
	memset(iv, 0x30, AES::BLOCKSIZE);
	sIV.size() <= AES::BLOCKSIZE ? memcpy(iv, sIV.c_str(), sIV.size()) : memcpy(iv, sIV.c_str(), AES::BLOCKSIZE);

	AES::Encryption aesEncryption((byte *)key, AES::MAX_KEYLENGTH);

	CFB_Mode_ExternalCipher::Encryption cfbEncryption(aesEncryption, iv);

	StreamTransformationFilter cfbEncryptor(cfbEncryption, new HexEncoder(new StringSink(outstr)), BlockPaddingSchemeDef::BlockPaddingScheme::NO_PADDING,
		true);
	cfbEncryptor.Put((byte *)plainText, strlen(plainText));
	cfbEncryptor.MessageEnd();

	return UTF8_TO_TCHAR(outstr.c_str());
}

FString  CFB_AESDecryptData(FString aes_content, FString aes_key, FString aes_IV, bool & result)
{
	std::string sKey = TCHAR_TO_UTF8(*aes_key);
	std::string sIV = TCHAR_TO_UTF8(*aes_IV);
	const char *cipherText = TCHAR_TO_UTF8(*aes_content);
	std::string outstr;

	try
	{
		//填key    
		SecByteBlock key(AES::MAX_KEYLENGTH);
		memset(key, 0x30, key.size());
		sKey.size() <= AES::MAX_KEYLENGTH ? memcpy(key, sKey.c_str(), sKey.size()) : memcpy(key, sKey.c_str(), AES::MAX_KEYLENGTH);

		//填iv    
		byte iv[AES::BLOCKSIZE];
		memset(iv, 0x30, AES::BLOCKSIZE);
		sIV.size() <= AES::BLOCKSIZE ? memcpy(iv, sIV.c_str(), sIV.size()) : memcpy(iv, sIV.c_str(), AES::BLOCKSIZE);


		CFB_Mode<AES >::Decryption cfbDecryption((byte *)key, AES::MAX_KEYLENGTH, iv);

		HexDecoder decryptor(new StreamTransformationFilter(cfbDecryption, new StringSink(outstr), BlockPaddingSchemeDef::BlockPaddingScheme::NO_PADDING,
			true));
		decryptor.Put((byte *)cipherText, strlen(cipherText));
		decryptor.MessageEnd();

		result = true;
	}
	catch (const std::exception&)
	{
		outstr = "error";
		UE_LOG(LogTemp, Error, TEXT("CFB_AESDecryptData failed!"));
		result = false;
	}
	return UTF8_TO_TCHAR(outstr.c_str());
}
#pragma endregion

#pragma region OFB

FString  OFB_AESEncryptData(FString aes_content, FString aes_key, FString aes_IV)
{
	//std::string sKey = "0123456789ABCDEF0123456789ABCDEF";
	std::string sKey = TCHAR_TO_UTF8(*aes_key);
	std::string sIV = TCHAR_TO_UTF8(*aes_IV);
	const char *plainText = TCHAR_TO_UTF8(*aes_content);
	std::string outstr;

	//填key    
	SecByteBlock key(AES::MAX_KEYLENGTH);
	memset(key, 0x30, key.size());
	sKey.size() <= AES::MAX_KEYLENGTH ? memcpy(key, sKey.c_str(), sKey.size()) : memcpy(key, sKey.c_str(), AES::MAX_KEYLENGTH);

	//填iv    
	byte iv[AES::BLOCKSIZE];
	memset(iv, 0x30, AES::BLOCKSIZE);
	sIV.size() <= AES::BLOCKSIZE ? memcpy(iv, sIV.c_str(), sIV.size()) : memcpy(iv, sIV.c_str(), AES::BLOCKSIZE);

	AES::Encryption aesEncryption((byte *)key, AES::MAX_KEYLENGTH);

	OFB_Mode_ExternalCipher::Encryption ofbEncryption(aesEncryption, iv);

	StreamTransformationFilter ofbEncryptor(ofbEncryption, new HexEncoder(new StringSink(outstr)), BlockPaddingSchemeDef::BlockPaddingScheme::NO_PADDING,
		true);
	ofbEncryptor.Put((byte *)plainText, strlen(plainText));
	ofbEncryptor.MessageEnd();

	return UTF8_TO_TCHAR(outstr.c_str());
}

FString  OFB_AESDecryptData(FString aes_content, FString aes_key, FString aes_IV, bool & result)
{
	std::string sKey = TCHAR_TO_UTF8(*aes_key);
	std::string sIV = TCHAR_TO_UTF8(*aes_IV);
	const char *cipherText = TCHAR_TO_UTF8(*aes_content);
	std::string outstr;

	try
	{
		//填key    
		SecByteBlock key(AES::MAX_KEYLENGTH);
		memset(key, 0x30, key.size());
		sKey.size() <= AES::MAX_KEYLENGTH ? memcpy(key, sKey.c_str(), sKey.size()) : memcpy(key, sKey.c_str(), AES::MAX_KEYLENGTH);

		//填iv    
		byte iv[AES::BLOCKSIZE];
		memset(iv, 0x30, AES::BLOCKSIZE);
		sIV.size() <= AES::BLOCKSIZE ? memcpy(iv, sIV.c_str(), sIV.size()) : memcpy(iv, sIV.c_str(), AES::BLOCKSIZE);


		OFB_Mode<AES >::Decryption ofbDecryption((byte *)key, AES::MAX_KEYLENGTH, iv);

		HexDecoder decryptor(new StreamTransformationFilter(ofbDecryption, new StringSink(outstr), BlockPaddingSchemeDef::BlockPaddingScheme::NO_PADDING,
			true));
		decryptor.Put((byte *)cipherText, strlen(cipherText));
		decryptor.MessageEnd();

		result = true;
	}
	catch (const std::exception&)
	{
		outstr = "error";
		UE_LOG(LogTemp, Error, TEXT("OFB_AESDecryptData failed!"));
		result = false;
	}
	return UTF8_TO_TCHAR(outstr.c_str());
}
#pragma endregion

#pragma region CTR

FString  CTR_AESEncryptData(FString aes_content, FString aes_key, FString aes_IV)
{
	//std::string sKey = "0123456789ABCDEF0123456789ABCDEF";
	std::string sKey = TCHAR_TO_UTF8(*aes_key);
	std::string sIV = TCHAR_TO_UTF8(*aes_IV);
	const char *plainText = TCHAR_TO_UTF8(*aes_content);
	std::string outstr;

	//填key    
	SecByteBlock key(AES::MAX_KEYLENGTH);
	memset(key, 0x30, key.size());
	sKey.size() <= AES::MAX_KEYLENGTH ? memcpy(key, sKey.c_str(), sKey.size()) : memcpy(key, sKey.c_str(), AES::MAX_KEYLENGTH);

	//填iv    
	byte iv[AES::BLOCKSIZE];
	memset(iv, 0x30, AES::BLOCKSIZE);
	sIV.size() <= AES::BLOCKSIZE ? memcpy(iv, sIV.c_str(), sIV.size()) : memcpy(iv, sIV.c_str(), AES::BLOCKSIZE);

	AES::Encryption aesEncryption((byte *)key, AES::MAX_KEYLENGTH);

	CTR_Mode_ExternalCipher::Encryption ctrEncryption(aesEncryption, iv);

	StreamTransformationFilter ctrEncryptor(ctrEncryption, new HexEncoder(new StringSink(outstr)), BlockPaddingSchemeDef::BlockPaddingScheme::NO_PADDING,
		true);
	ctrEncryptor.Put((byte *)plainText, strlen(plainText));
	ctrEncryptor.MessageEnd();

	return UTF8_TO_TCHAR(outstr.c_str());
}

FString  CTR_AESDecryptData(FString aes_content, FString aes_key, FString aes_IV, bool & result)
{
	std::string sKey = TCHAR_TO_UTF8(*aes_key);
	std::string sIV = TCHAR_TO_UTF8(*aes_IV);
	const char *cipherText = TCHAR_TO_UTF8(*aes_content);
	std::string outstr;

	try
	{
		//填key    
		SecByteBlock key(AES::MAX_KEYLENGTH);
		memset(key, 0x30, key.size());
		sKey.size() <= AES::MAX_KEYLENGTH ? memcpy(key, sKey.c_str(), sKey.size()) : memcpy(key, sKey.c_str(), AES::MAX_KEYLENGTH);

		//填iv    
		byte iv[AES::BLOCKSIZE];
		memset(iv, 0x30, AES::BLOCKSIZE);
		sIV.size() <= AES::BLOCKSIZE ? memcpy(iv, sIV.c_str(), sIV.size()) : memcpy(iv, sIV.c_str(), AES::BLOCKSIZE);


		CTR_Mode<AES >::Decryption ctrDecryption((byte *)key, AES::MAX_KEYLENGTH, iv);

		HexDecoder decryptor(new StreamTransformationFilter(ctrDecryption, new StringSink(outstr), BlockPaddingSchemeDef::BlockPaddingScheme::NO_PADDING,
			true));
		decryptor.Put((byte *)cipherText, strlen(cipherText));
		decryptor.MessageEnd();

		result = true;
	}
	catch (const std::exception&)
	{
		outstr = "error";
		UE_LOG(LogTemp, Error, TEXT("CTR_AESDecryptData failed!"));
		result = false;
	}
	return UTF8_TO_TCHAR(outstr.c_str());
}

#pragma endregion


FString UTBBCryptBPLibrary::AESFunctionLib(FString inString, FString aes_key, FString aes_IV, ECryptMode mode, ECryActionType action)
{
	FString  OutString = "";
	//std::string sKey = TCHAR_TO_UTF8(*aes_key);
	//const char *plainText = TCHAR_TO_UTF8(*inString);
	//std::string sIV = TCHAR_TO_UTF8(*aes_IV);
	bool test = false;
	switch (action)
	{
	case ECryActionType::Encrypt:
		switch (mode)
		{
		case ECryptMode::ECB:
			OutString = ECB_AESEncryptData(inString, aes_key);
			break;
		case ECryptMode::CBC:
			OutString = CBC_AESEncryptData(inString, aes_key, aes_IV);
			break;
		case ECryptMode::CFB:
			OutString = CFB_AESEncryptData(inString, aes_key, aes_IV);
			break;
		case ECryptMode::OFB:
			OutString = OFB_AESEncryptData(inString, aes_key, aes_IV);
			break;
		case ECryptMode::CTR:
			OutString = CTR_AESEncryptData(inString, aes_key, aes_IV);
			break;
		default:
			break;
		}
		break;
	case ECryActionType::Decrypt:
		switch (mode)
		{
		case ECryptMode::ECB:
			OutString = ECB_AESDecryptData(inString, aes_key,test);
			break;
		case ECryptMode::CBC:
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
