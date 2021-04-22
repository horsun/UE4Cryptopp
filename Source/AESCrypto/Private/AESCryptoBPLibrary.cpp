// Copyright 1998-2019 Epic Games, Inc. All Rights Reserved.

#include "AESCryptoBPLibrary.h"
//#include "aes.h"
#include "../../ThirdParty/include/aes.h"  //防止和引擎内置的aes冲突
#include "hex.h"         // StreamTransformationFilter  
#include "modes.h"	     // CFB_Mode  
#include <iostream>   // std:cerr    
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
string ECB_EnCrypto(string inPlain, BlockPaddingSchemeDef::BlockPaddingScheme padding)
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
	             )
	);
	//这一步是通过StringSource 将cipher 密文转成可以正常打印阅读的 密文，主要关注HexEncoder 
	StringSource(cipher, true,
	             new HexEncoder(
		             new StringSink(cipherOut)
	             )
	);
	return cipherOut;
}

string ECB_DeCrypto(string inCipher, BlockPaddingSchemeDef::BlockPaddingScheme padding)
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
	               )
	);
	return plainOut;
}
#pragma endregion
#pragma region CBC
string CBC_EnCrypto(string inPlain, BlockPaddingSchemeDef::BlockPaddingScheme padding)
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
	             )
	);
	//这一步是通过StringSource 将cipher 密文转成可以正常打印阅读的 密文，主要关注HexEncoder 
	StringSource(cipher, true,
	             new HexEncoder(
		             new StringSink(cipherOut)
	             )
	);
	return cipherOut;
}

string CBC_DeCrypto(string inCipher, BlockPaddingSchemeDef::BlockPaddingScheme padding)
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
	               )
	);
	return plainOut;
}
#pragma endregion
#pragma region CFB
string CFB_EnCrypto(string inPlain, BlockPaddingSchemeDef::BlockPaddingScheme padding)
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
	             )
	);
	//这一步是通过StringSource 将cipher 密文转成可以正常打印阅读的 密文，主要关注HexEncoder 
	StringSource(cipher, true,
	             new HexEncoder(
		             new StringSink(cipherOut)
	             )
	);
	return cipherOut;
}

string CFB_DeCrypto(string inCipher, BlockPaddingSchemeDef::BlockPaddingScheme padding)
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
	               )
	);
	return plainOut;
}
#pragma endregion
#pragma region OFB
string OFB_EnCrypto(string inPlain, BlockPaddingSchemeDef::BlockPaddingScheme padding)
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
	             )
	);
	//这一步是通过StringSource 将cipher 密文转成可以正常打印阅读的 密文，主要关注HexEncoder 
	StringSource(cipher, true,
	             new HexEncoder(
		             new StringSink(cipherOut)
	             )
	);
	return cipherOut;
}

string OFB_DeCrypto(string inCipher, BlockPaddingSchemeDef::BlockPaddingScheme padding)
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
	               )
	);
	return plainOut;
}
#pragma endregion
#pragma region CTR
string CTR_EnCrypto(string inPlain, BlockPaddingSchemeDef::BlockPaddingScheme padding)
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
	             )
	);
	//这一步是通过StringSource 将cipher 密文转成可以正常打印阅读的 密文，主要关注HexEncoder 
	StringSource(cipher, true,
	             new HexEncoder(
		             new StringSink(cipherOut)
	             )
	);
	return cipherOut;
}

string CTR_DeCrypto(string inCipher, BlockPaddingSchemeDef::BlockPaddingScheme padding)
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
	               )
	);
	return plainOut;
}
#pragma endregion
#pragma region ECBFile Function
bool AESFunctionClass::AESFileEncrypto(FString Path, FString FileName)
{
	//判断文件存在
	if (!FPaths::FileExists(*Path))
	{
		return false;
	}
	//获取key
	SecByteBlock Key = GetKey();

	//读取文件
	TArray<uint8> Reader;
	FFileHelper::LoadFileToArray(Reader, *Path);
	//定义一个二进制密文
	vector<byte> cipher;
	//设置长度
	cipher.resize(Reader.Num() + AES::BLOCKSIZE);
	//定义个存二进制队列
	ArraySink as(&cipher[0], cipher.size());

	ECB_Mode<AES>::Encryption e;
	e.SetKey((byte*)Key, AES::MAX_KEYLENGTH);

	//通过arraySource和encryption对文件流进行加密，并存在arraysink对象中
	ArraySource(Reader.GetData(), Reader.Num(), true,
	            new StreamTransformationFilter(e, new Redirector(as),
	                                           BlockPaddingSchemeDef::BlockPaddingScheme::PKCS_PADDING));

	cipher.resize(as.TotalPutLength());
	TArray<uint8> data;
	data.Append(cipher.data(), cipher.size());
	//设置新文件保存
	FString Savepath = FPaths::GetPath(Path) + "/" + FileName;
	FFileHelper::SaveArrayToFile(data, *Savepath);
	return true;
};

bool AESFunctionClass::AESFileDecrypto(FString Path, FString FileName)
{
	//判断文件存在
	if (!FPaths::FileExists(*Path))
	{
		return false;
	}
	//读取文件
	TArray<uint8> Reader;
	FFileHelper::LoadFileToArray(Reader, *Path);

	vector<byte> recover;
	recover.resize(Reader.Num());
	ArraySink as(&recover[0], recover.size()); //定义个存二进制队列

	SecByteBlock Key = GetKey();
	ECB_Mode<AES>::Decryption de;
	de.SetKey((byte*)Key, AES::MAX_KEYLENGTH);

	ArraySource(Reader.GetData(), Reader.Num(), true,
	            new StreamTransformationFilter(de, new Redirector(as),
	                                           BlockPaddingSchemeDef::BlockPaddingScheme::PKCS_PADDING));
	recover.resize(as.TotalPutLength());
	TArray<uint8> data;
	data.Append(recover.data(), recover.size());
	FString SavePath = FPaths::GetPath(Path) + "/" + FileName;
	FFileHelper::SaveArrayToFile(data, *SavePath);
	return false;
};

bool  AESFunctionClass::MediaDecrypto(FString Path, TArray<uint8>& OutPut)
{
	if (!FPaths::FileExists(*Path))
	{
		return false;
	}
	TArray<uint8> Reader;
	FFileHelper::LoadFileToArray(Reader, *Path);

	vector<byte> recover;
	recover.resize(Reader.Num());
	ArraySink as(&recover[0], recover.size()); //定义个存二进制队列

	SecByteBlock Key = GetKey();
	ECB_Mode<AES>::Decryption de;
	de.SetKey((byte*)Key, AES::MAX_KEYLENGTH);

	ArraySource(Reader.GetData(), Reader.Num(), true,
	            new StreamTransformationFilter(de, new Redirector(as),
	                                           BlockPaddingSchemeDef::BlockPaddingScheme::PKCS_PADDING));
	recover.resize(as.TotalPutLength());
	OutPut.Append(recover.data(), recover.size());
	return true;
}
#pragma endregion
string AESFunctionClass::AESFunctionLib(string inString, ECryptMode mode, ECryActionType action, ECryptPadding padding)
{
	string OutString = "";
	try
	{
		switch (action)
		{
		case ECryActionType::Encrypt:
			switch (mode)
			{
			case ECryptMode::ECB:
				OutString = ECB_EnCrypto(inString, BlockPaddingSchemeDef::BlockPaddingScheme(int(padding)));
				break;
			case ECryptMode::CBC:
				OutString = CBC_EnCrypto(inString, BlockPaddingSchemeDef::BlockPaddingScheme(int(padding)));
				break;
			case ECryptMode::CFB:
				OutString = CFB_EnCrypto(inString, BlockPaddingSchemeDef::BlockPaddingScheme(int(padding)));
				break;
			case ECryptMode::OFB:
				OutString = OFB_EnCrypto(inString, BlockPaddingSchemeDef::BlockPaddingScheme(int(padding)));
				break;
			case ECryptMode::CTR:
				OutString = CTR_EnCrypto(inString, BlockPaddingSchemeDef::BlockPaddingScheme(int(padding)));
				break;
			default:
				break;
			}
			break;
		case ECryActionType::Decrypt:
			switch (mode)
			{
			case ECryptMode::ECB:
				OutString = ECB_DeCrypto(inString, BlockPaddingSchemeDef::BlockPaddingScheme(int(padding)));
				break;
			case ECryptMode::CBC:
				OutString = CBC_DeCrypto(inString, BlockPaddingSchemeDef::BlockPaddingScheme(int(padding)));
				break;
			case ECryptMode::CFB:
				OutString = CFB_DeCrypto(inString, BlockPaddingSchemeDef::BlockPaddingScheme(int(padding)));
				break;
			case ECryptMode::OFB:
				OutString = OFB_DeCrypto(inString, BlockPaddingSchemeDef::BlockPaddingScheme(int(padding)));
				break;
			case ECryptMode::CTR:
				OutString = CTR_DeCrypto(inString, BlockPaddingSchemeDef::BlockPaddingScheme(int(padding)));
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
		std::cout << e.what() << endl;
	}

	return OutString;
};
