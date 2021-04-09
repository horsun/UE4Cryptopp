// Copyright 1998-2019 Epic Games, Inc. All Rights Reserved.

#include "AESCryptoBPLibrary.h"
//#include "aes.h"
#include "../../ThirdParty/include/aes.h"  //防止和引擎内置的aes冲突
#include "hex.h"         // StreamTransformationFilter  
#include "modes.h"	     // CFB_Mode  
#include <iostream>   // std:cerr    
#include <sstream>   // std::stringstream    
#include <string>
#include "channels.h"
#include "mqueue.h"
#include "Serialization/ArrayReader.h"
#include "Misc/FileHelper.h"
#include "Misc/Paths.h"
using namespace std;
using namespace CryptoPP;
#pragma comment(lib, "cryptlib.lib" )



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
FString ECB_EnCrypto(string inPlain, BlockPaddingSchemeDef::BlockPaddingScheme padding)
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
			, padding
			, true
		)
	);
	//这一步是通过StringSource 将cipher 密文转成可以正常打印阅读的 密文，主要关注HexEncoder 
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(cipherOut)
		)
	);
	UE_LOG(LogTemp, Warning, TEXT(" the cipher:%s"), UTF8_TO_TCHAR(cipherOut.c_str()));
	return UTF8_TO_TCHAR(cipherOut.c_str());
}

FString ECB_DeCrypto(string inCipher, BlockPaddingSchemeDef::BlockPaddingScheme padding)
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
			, padding
			, true
		)
	);
	UE_LOG(LogTemp, Warning, TEXT(" the recovered:%s"), UTF8_TO_TCHAR(plainOut.c_str()));
	return UTF8_TO_TCHAR(plainOut.c_str());
}
#pragma endregion
#pragma region CBC
FString CBC_EnCrypto(string inPlain, BlockPaddingSchemeDef::BlockPaddingScheme padding)
{
	string cipher; //存密文
	string cipherOut; //存输出的string密文
	SecByteBlock Key = GetKey();
	CBC_Mode<AES>::Encryption e;
	e.SetKeyWithIV((byte*)Key, AES::MAX_KEYLENGTH, GetIV());
	//这一步StingSource是将明文通过 encryption进行加密，得到cipher密文
	StringSource(inPlain, true,
		new StreamTransformationFilter(e,
			new StringSink(cipher)
			, padding
			, true
		)
	);
	//这一步是通过StringSource 将cipher 密文转成可以正常打印阅读的 密文，主要关注HexEncoder 
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(cipherOut)
		)
	);
	UE_LOG(LogTemp, Warning, TEXT(" the cipher:%s"), UTF8_TO_TCHAR(cipherOut.c_str()));
	return UTF8_TO_TCHAR(cipherOut.c_str());
}
FString CBC_DeCrypto(string inCipher, BlockPaddingSchemeDef::BlockPaddingScheme padding)
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
	d.SetKeyWithIV((byte*)Key, AES::MAX_KEYLENGTH, GetIV());
	StringSource s(plain, true,
		new StreamTransformationFilter(d,
			new StringSink(plainOut)
			, padding
			, true
		)
	);
	UE_LOG(LogTemp, Warning, TEXT(" the recovered:%s"), UTF8_TO_TCHAR(plainOut.c_str()));
	return UTF8_TO_TCHAR(plainOut.c_str());
}
#pragma endregion
#pragma region CFB
FString CFB_EnCrypto(string inPlain, BlockPaddingSchemeDef::BlockPaddingScheme padding)
{
	string cipher; //存密文
	string cipherOut; //存输出的string密文
	SecByteBlock Key = GetKey();
	CFB_Mode<AES>::Encryption e;
	e.SetKeyWithIV((byte*)Key, AES::MAX_KEYLENGTH, GetIV());
	//这一步StingSource是将明文通过 encryption进行加密，得到cipher密文
	StringSource(inPlain, true,
		new StreamTransformationFilter(e,
			new StringSink(cipher)
			, padding
			, true
		)
	);
	//这一步是通过StringSource 将cipher 密文转成可以正常打印阅读的 密文，主要关注HexEncoder 
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(cipherOut)
		)
	);
	UE_LOG(LogTemp, Warning, TEXT(" the cipher:%s"), UTF8_TO_TCHAR(cipherOut.c_str()));
	return UTF8_TO_TCHAR(cipherOut.c_str());
}
FString CFB_DeCrypto(string inCipher, BlockPaddingSchemeDef::BlockPaddingScheme padding)
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
	d.SetKeyWithIV((byte*)Key, AES::MAX_KEYLENGTH, GetIV());
	StringSource s(plain, true,
		new StreamTransformationFilter(d,
			new StringSink(plainOut)
			, padding
			, true
		)
	);
	UE_LOG(LogTemp, Warning, TEXT(" the recovered:%s"), UTF8_TO_TCHAR(plainOut.c_str()));
	return UTF8_TO_TCHAR(plainOut.c_str());
}
#pragma endregion
#pragma region OFB
FString OFB_EnCrypto(string inPlain, BlockPaddingSchemeDef::BlockPaddingScheme padding)
{
	string cipher; //存密文
	string cipherOut; //存输出的string密文
	SecByteBlock Key = GetKey();
	OFB_Mode<AES>::Encryption e;
	e.SetKeyWithIV((byte*)Key, AES::MAX_KEYLENGTH, GetIV());
	//这一步StingSource是将明文通过 encryption进行加密，得到cipher密文
	StringSource(inPlain, true,
		new StreamTransformationFilter(e,
			new StringSink(cipher)
			, padding
			, true
		)
	);
	//这一步是通过StringSource 将cipher 密文转成可以正常打印阅读的 密文，主要关注HexEncoder 
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(cipherOut)
		)
	);
	UE_LOG(LogTemp, Warning, TEXT(" the cipher:%s"), UTF8_TO_TCHAR(cipherOut.c_str()));
	return UTF8_TO_TCHAR(cipherOut.c_str());
}
FString OFB_DeCrypto(string inCipher, BlockPaddingSchemeDef::BlockPaddingScheme padding)
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
	d.SetKeyWithIV((byte*)Key, AES::MAX_KEYLENGTH, GetIV());
	StringSource s(plain, true,
		new StreamTransformationFilter(d,
			new StringSink(plainOut)
			, padding
			, true
		)
	);
	UE_LOG(LogTemp, Warning, TEXT(" the recovered:%s"), UTF8_TO_TCHAR(plainOut.c_str()));
	return UTF8_TO_TCHAR(plainOut.c_str());
}
#pragma endregion
#pragma region CTR
FString CTR_EnCrypto(string inPlain, BlockPaddingSchemeDef::BlockPaddingScheme padding)
{
	string cipher; //存密文
	string cipherOut; //存输出的string密文
	SecByteBlock Key = GetKey();
	CTR_Mode<AES>::Encryption e;
	e.SetKeyWithIV((byte*)Key, AES::MAX_KEYLENGTH, GetIV());
	//这一步StingSource是将明文通过 encryption进行加密，得到cipher密文
	StringSource(inPlain, true,
		new StreamTransformationFilter(e,
			new StringSink(cipher)
			, padding
			, true
		)
	);
	//这一步是通过StringSource 将cipher 密文转成可以正常打印阅读的 密文，主要关注HexEncoder 
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(cipherOut)
		)
	);
	UE_LOG(LogTemp, Warning, TEXT(" the cipher:%s"), UTF8_TO_TCHAR(cipherOut.c_str()));
	return UTF8_TO_TCHAR(cipherOut.c_str());
}
FString CTR_DeCrypto(string inCipher, BlockPaddingSchemeDef::BlockPaddingScheme padding)
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
	d.SetKeyWithIV((byte*)Key, AES::MAX_KEYLENGTH, GetIV());
	StringSource s(plain, true,
		new StreamTransformationFilter(d,
			new StringSink(plainOut)
			, padding
			, true
		)
	);
	UE_LOG(LogTemp, Warning, TEXT(" the recovered:%s"), UTF8_TO_TCHAR(plainOut.c_str()));
	return UTF8_TO_TCHAR(plainOut.c_str());
}
#pragma endregion 
#pragma region ECBFile Function
bool FileEncrypto(FString Path, FString FileName)
{
	//判断文件存在
	if (!FPaths::FileExists(*Path))
	{
		return false;
	}
	//获取key
	SecByteBlock Key = GetKey();

	//读取文件
	FArrayReader * Reader = new FArrayReader;
	FFileHelper::LoadFileToArray(*Reader, *Path);
	//定义一个二进制密文
	vector<byte> cipher;
	//设置长度
	cipher.resize(Reader->TotalSize() + AES::BLOCKSIZE);
	//定义个存二进制队列
	ArraySink as(&cipher[0], cipher.size());

	ECB_Mode<AES>::Encryption e;
	e.SetKey((byte*)Key, AES::MAX_KEYLENGTH);

	//通过arraySource和encryption对文件流进行加密，并存在arraysink对象中
	ArraySource(Reader->GetData(), Reader->TotalSize(), true, new StreamTransformationFilter(e, new Redirector(as), BlockPaddingSchemeDef::BlockPaddingScheme::PKCS_PADDING, true));

	cipher.resize(as.TotalPutLength());
	TArray<uint8> data;
	data.Append(cipher.data(), cipher.size());
	//设置新文件保存
	FString Savepath = FPaths::GetPath(Path) + "/" + FileName;
	FFileHelper::SaveArrayToFile(data, *Savepath);
	return true;
};
bool FileDecrypto(FString Path, FString FileName)
{
	//判断文件存在
	if (!FPaths::FileExists(*Path))
	{
		return false;
	}
	//读取文件
	FArrayReader * Reader = new FArrayReader;
	FFileHelper::LoadFileToArray(*Reader, *Path);

	vector<byte> recover;
	recover.resize(Reader->TotalSize());
	ArraySink as(&recover[0], recover.size()); //定义个存二进制队列

	SecByteBlock Key = GetKey();
	ECB_Mode<AES>::Decryption de;
	de.SetKey((byte*)Key, AES::MAX_KEYLENGTH);

	ArraySource(Reader->GetData(), Reader->TotalSize(), true, new StreamTransformationFilter(de, new Redirector(as), BlockPaddingSchemeDef::BlockPaddingScheme::PKCS_PADDING, true));
	recover.resize(as.TotalPutLength());
	TArray<uint8> data;
	data.Append(recover.data(), recover.size());
	FString SavePath = FPaths::GetPath(Path) + "/" + FileName;
	FFileHelper::SaveArrayToFile(data, *SavePath);
	return false;
};
#pragma endregion
FString UAESCryptoBPLibrary::AESFunctionLib(FString inString, ECryptMode mode, ECryActionType action, ECryptPadding padding)
{
	FString OutString = "";
	const string InStringTarget = TCHAR_TO_UTF8(*inString);
	try
	{
		switch (action)
		{
		case ECryActionType::Encrypt:
			switch (mode)
			{
			case ECryptMode::ECB:
				OutString = ECB_EnCrypto(InStringTarget, BlockPaddingSchemeDef::BlockPaddingScheme(int(padding)));
				break;
			case ECryptMode::CBC:
				OutString = CBC_EnCrypto(InStringTarget, BlockPaddingSchemeDef::BlockPaddingScheme(int(padding)));
				break;
			case ECryptMode::CFB:
				OutString = CFB_EnCrypto(InStringTarget, BlockPaddingSchemeDef::BlockPaddingScheme(int(padding)));
				break;
			case ECryptMode::OFB:
				OutString = OFB_EnCrypto(InStringTarget, BlockPaddingSchemeDef::BlockPaddingScheme(int(padding)));
				break;
			case ECryptMode::CTR:
				OutString = CTR_EnCrypto(InStringTarget, BlockPaddingSchemeDef::BlockPaddingScheme(int(padding)));
				break;
			default:
				break;
			}
			break;
		case ECryActionType::Decrypt:
			switch (mode)
			{
			case ECryptMode::ECB:
				OutString = ECB_DeCrypto(InStringTarget, BlockPaddingSchemeDef::BlockPaddingScheme(int(padding)));
				break;
			case ECryptMode::CBC:
				OutString = CBC_DeCrypto(InStringTarget, BlockPaddingSchemeDef::BlockPaddingScheme(int(padding)));
				break;
			case ECryptMode::CFB:
				OutString = CFB_DeCrypto(InStringTarget, BlockPaddingSchemeDef::BlockPaddingScheme(int(padding)));
				break;
			case ECryptMode::OFB:
				OutString = OFB_DeCrypto(InStringTarget, BlockPaddingSchemeDef::BlockPaddingScheme(int(padding)));
				break;
			case ECryptMode::CTR:
				OutString = CTR_DeCrypto(InStringTarget, BlockPaddingSchemeDef::BlockPaddingScheme(int(padding)));
				break;
			default:
				break;
			}
			break;
		default:
			break;
		}
	}
	catch (const std::exception& e)
	{
		UE_LOG(LogTemp, Error, TEXT("Crash for AESCripto Function :%s"), *FString(e.what()))
	}

	return OutString;
}

void UAESCryptoBPLibrary::testfileEn()
{
	//FileEncrypto("C:/Users/10008/Desktop/AndroidTest/decrypt7.mp4", "1");
}

void UAESCryptoBPLibrary::testfileDe()
{
	//FileDecrypto("C:/Users/10008/Desktop/AndroidTest/decrypt7.mp4.b");
}
