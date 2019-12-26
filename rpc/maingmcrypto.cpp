#include "rpc/server.h"
#include "sync.h"
#include "util.h"
#include "rpc/protocol.h"
#include "utilstrencodings.h"
#include <univalue.h>


#include <mutex>
#include <condition_variable>

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <string>
#include <fstream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ossl_typ.h>
#include <openssl/e_os2.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
/*
#include <cryptography.h>
#include <base_64.h>
#include <base_58.h>
#include <hexTranscode.h>
*/
#include "crypto/crypto_include/cryptography.h"
#include "crypto/crypto_include/base_64.h"
#include "crypto/crypto_include/base_58.h"
#include "crypto/crypto_include/hexTranscode.h"
#include "crypto/crypto_include/judgeInputParameters.h"


using namespace std;
//0
UniValue getinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "getinfo\n"
            "\nReturns the number of blocks in the longest blockchain.\n"
            "\nResult:\n"
            "n    (numeric) The current block count\n"
            "\nExamples:\n"
            + HelpExampleCli("getinfo", "")
            + HelpExampleRpc("getinfo", "")
        );

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("result", "SUCCESS"));
    return ret;
}


/*******************************************************************************
* 1 SM2
* 函数介绍: *1.1 SM2_Key()函数
* 输入参数：
           json transcode:转码方式--base64/base58/16进制转码.
* 输出参数: string  transcode：转码方式--base64/base58/16进制转码
           int struContext->iPubKeyLen ：输出SM2公钥长度
           unsigned char* struContext->cPubKey：输出SM2公钥值
          
* 返 回 值: 0: 成功         <0: 失败
*注意：产生公钥sm2publicKey.pem和私钥sm2privateKey.pem。
*******************************************************************************/
UniValue sm2generatekeypairs(const JSONRPCRequest& request)
{
    
    if (request.fHelp || request.params.size() < 0 || request.params.size() > 1 )
    {
        throw runtime_error(
        "sm2generatekeypairs\n"
         "\nReturns  public key and private key generated from sm2 .\n"
        "\nArguments:\n"
        "1. \"transcode\"     (string, optional) The transcode is base64/hex, and hex is setted as default parameter..\n" 
        "\nResult:\n"
        "{                    (json object)\n"   
       // "  \"result\"         (string, The sm2 successfully product public key and private key. )\n"
        "  \"transcode\"      (string, This is the encode . )\n"
        "  \"publicKeyLen\"   (string, This is the length of publicKey. )\n"
        "  \"publicKey\"      (string, The publicKey generated from sm2\n"
        "}\n"
        "\nExamples:\n"
        + HelpExampleCli("sm2generatekeypairs", "\"transcode\" ")
        + HelpExampleRpc("sm2generatekeypairs", "\"transcode\" ")
         );
    }
     StruCrypto *struCrypto = new StruCrypto;
     ClassSM2 classSM2;
     UniValue result(UniValue::VOBJ);
     int ret = -1;
    JudgeInputParameters *judgeInputPara = new JudgeInputParameters;
   

    struCrypto->strTranscode = "hex";
    if(1 == request.params.size())
    {
        struCrypto->strTranscode = request.params[0].get_str();
    }

    /*judge input parameters*/
    judgeInputPara->JudgeSM2Key(struCrypto);

    struCrypto->strAlgorithm = "sm2";
    if (0 == struCrypto->strAlgorithm.compare("SM2") || 0 == struCrypto->strAlgorithm.compare("sm2") )
    {
        StruSM2Context *struContext = new StruSM2Context;
	    memset(struContext, 0, sizeof(StruSM2Context));
        ret = classSM2.SM2_Key(struContext);
		if(ret != 0)
		{
			 cout <<"SM2_Key  doesn't successfully product sm2privateKey.pem and sm2publicKeu.pem!" <<endl;
             LogPrintf("SM2_Key  doesn't  successfully product sm2privateKey.pem and sm2publicKeu.pem!\n");
             throw JSONRPCError(SM2_KEY_ERROR, "SM2_Key  doesn't successfully product sm2privateKey.pem and sm2publicKeu.pem!");
		}	

        FILE* fpPubKey;
        fpPubKey = fopen("sm2publicKey.pem","r");
        if(NULL == fpPubKey)
        {
            cout << " Cannot open sm2publicKey.pem by read."<<endl;
            LogPrintf("Cannot open sm2publicKey.pem by read.\n");
            throw JSONRPCError(SM2_PUBLIC_KEY_READ_ERROR, "Cannot open sm2publicKey.pem by read.");
        }
        
        struContext->cPubKey = new uint8_t[MSG_LEN]; 
        memset(struContext->cPubKey, 0, MSG_LEN);
        struContext->iPubKeyLen = 0;
        struContext->iPubKeyLen = fread(struContext->cPubKey, 1, MSG_LEN, fpPubKey);
        if(struContext->iPubKeyLen < 0)
        {
            cout <<"Cannot read the datum  from sm2publicKey.pem."<<endl;
            LogPrintf("Cannot read the datum  from sm2publicKey.pem.\n");
            throw JSONRPCError(SM2_PUBLIC_KEY_READ_ERROR, "Cannot read the datum  from sm2publicKey.pem.");
        }    
        cout<<"struContext->iPubKeyLen="<<struContext->iPubKeyLen<<", struContext->cPubKey="<<struContext->cPubKey<<endl;
        

         //编码
        if( 0 == struCrypto->strTranscode.compare("BASE64") || 0 == struCrypto->strTranscode.compare("base64"))
        {
            
            Base64 *base64 = new Base64();
            string *strPubKeyToBase64 = new string[MSG_LEN_TRANSCODE];  
            memset(strPubKeyToBase64, 0, MSG_LEN_TRANSCODE);  
            size_t strPubKeyToBase64Len = 0;
            strPubKeyToBase64Len = base64->Base64Encode(struContext->cPubKey, (int) struContext->iPubKeyLen, strPubKeyToBase64);                  
            if(strPubKeyToBase64Len <= 0)
            {
                cout <<"The base64 doesn't encode at sm2generatekeypairs. "<<endl;
                LogPrintf("The base64 doesn't encode at sm2generatekeypairs \n");
                throw JSONRPCError(BASE64_ENCODE_ERROR, "The base64 doesn't encode at sm2generatekeypairs. ");
            }
            
            cout<<"base64 encode :strPubKeyToBase64Len = "<< strPubKeyToBase64Len<<", *strPubKeyToBase64="<< *strPubKeyToBase64<<endl;
            LogPrintf("base64 encode :strPubKeyToBase64Len = %d, *strPubKeyToBase64 = %s\n", strPubKeyToBase64Len,  *strPubKeyToBase64);
              
         //   result.push_back(Pair("result", "The sm2 successfully product the public and private key."));
            result.push_back(Pair("transcode", struCrypto->strTranscode));
            result.push_back(Pair("publicKeyLen", strPubKeyToBase64Len));
            result.push_back(Pair("publicKey", *strPubKeyToBase64));

            delete[] strPubKeyToBase64;
            delete base64;
        }
        else if( 0 == struCrypto->strTranscode.compare("BASE58") || 0 == struCrypto->strTranscode.compare("base58"))
        {
            Base58 *base58 = new Base58();
            string *strPubKeyToBase58 = new string[MSG_LEN_TRANSCODE];   
            memset(strPubKeyToBase58, 0, MSG_LEN_TRANSCODE); 
            size_t strPubKeyToBase58Len = 0;
            strPubKeyToBase58Len =  base58->Base58Encode(struContext->cPubKey, (int) struContext->iPubKeyLen, strPubKeyToBase58);                  
            if(strPubKeyToBase58Len <= 0)
            {
                cout <<"The base58 doesn't encode at sm2generatekeypairs."<<endl;
                LogPrintf("The base58 doesn't encode at sm2generatekeypairs. \n");
                throw JSONRPCError(BASE58_ENCODE_ERROR, "The base58 doesn't encode at sm2generatekeypairs. ");
                //return -1;
            }  
            cout<<"base58 encode : strPubKeyToBase58Len= "<< strPubKeyToBase58Len<<", *strPubKeyToBase58="<< *strPubKeyToBase58<<endl;
            LogPrintf("base58 encode :strPubKeyToBase58Len = %d, *strPubKeyToBase58 = %s\n", strPubKeyToBase58Len, *strPubKeyToBase58);
        
        //    result.push_back(Pair("result", "The sm2 successfully product the public and private key."));
            result.push_back(Pair("transcode", struCrypto->strTranscode));
            result.push_back(Pair("publicKeyLen", strPubKeyToBase58Len));
            result.push_back(Pair("publicKey", *strPubKeyToBase58));

            delete[] strPubKeyToBase58;
            delete base58;
        }
        else if( 0 == struCrypto->strTranscode.compare("HEX") || 0 == struCrypto->strTranscode.compare("hex"))
        {
            HexTranscode *hexTranscode = new HexTranscode();
            string *strPubKeyToHex = new string[MSG_LEN_TRANSCODE];  
            memset(strPubKeyToHex, 0,  MSG_LEN_TRANSCODE);  
            size_t strPubKeyToHexLen = 0;
            strPubKeyToHexLen = hexTranscode->HexEncode(struContext->cPubKey, (int) struContext->iPubKeyLen, strPubKeyToHex);                  
            if(strPubKeyToHexLen <= 0)
            {
                cout <<"The hex is doesn't encode at sm2generatekeypairs."<<endl;
                LogPrintf("The hex is doesn't encode at sm2generatekeypairs.\n");
                throw JSONRPCError(HEX_ENCODE_ERROR, "The hex is doesn't encode at sm2generatekeypairs. ");
                //return -1;
            }  
            cout<<"hex encode : strPubKeyToHexLen= "<< strPubKeyToHexLen<<", *strPubKeyToHex="<< *strPubKeyToHex<<endl;
            LogPrintf("hex encode :strPubKeyToHexLen = %d , *strPubKeyToHex = %s\n", strPubKeyToHexLen, *strPubKeyToHex );
         
         //   result.push_back(Pair("result", "The sm2 successfully product the public and private key."));
            result.push_back(Pair("transcode", struCrypto->strTranscode));
            result.push_back(Pair("publicKeyLen", strPubKeyToHexLen));
            result.push_back(Pair("publicKey", *strPubKeyToHex));

            delete[] strPubKeyToHex;
            delete hexTranscode;
        }
        else
        {
            cout <<" The transcode is not encode to base64 、 base58 or hex at sm2generatekeypairs."<<endl;
            LogPrintf("The transcode is not encode to base64 、 base58 or hex at sm2generatekeypairs.\n");
            throw JSONRPCError(TRANSCODE_ERROR, "The  transcode is not encode to base64 、 base58 or hex at sm2generatekeypairs.");
            //return -1;
        }
      
        fclose(fpPubKey);
        delete[] struContext->cPubKey; 
        delete struContext;
        delete struCrypto;
        delete judgeInputPara;
		
    } 
    else
	{
		cout << "The algorithm is not SM2 at sm2generatekeypairs." <<endl;
        LogPrintf("The algorithm is not SM2 at sm2generatekeypairs.\n");
        throw JSONRPCError(SM2_ERROR, "The algorithm is not SM2 at sm2generatekeypairs.");
		//return -1;
	}

    return result;
}


/*******************************************************************************
* 1 SM2
* 函数介绍: *1.2 sm2getciphertext()：SM2加密函数
* 输入参数：json plaintext ：明文        
           json transcode ：转码方式--base64/base58/16进制转码         
* 输出参数: string  transcode：转码方式--base64/base58/16进制转码
           int strCipherOutLen ：输出SM2加密后编码密文的长度
           string* strCipherOut：输出SM2加密后编码密文
          
* 返 回 值: 0: 成功         <0: 失败
* 注意：默认使用公钥sm2publicKey.pem
*******************************************************************************/
UniValue sm2getciphertext(const JSONRPCRequest& request)
{
    
    if (request.fHelp || request.params.size() < 1 ||  request.params.size() > 2)
    {
        throw runtime_error(
        "sm2getciphertext \n"
        "\nReturns  ciphertext encrypted from plaintext  by public key.\n"
        "\nArguments:\n"
        "1. \"plaintext\"     (string, required) The plaintext is the input data.\n"
        "2. \"transcode\"     (string, optional)The transcode is base64/hex,hex is setted as default parameter.\n"  
        "\nResult:\n"
         "{                      (json object)\n"   
     //   "  \"result\"         (string, The sm2 successfully encrpyt. )\n"
        "  \"transcode\"      (string, This is the encode . )\n"
        "  \"ciphertextLen\"   (string, This is the length of ciphertext. )\n"
        "  \"ciphertext\"      (string, The ciphertext encrypted  from plaintext by public key.\n"
        "}\n"
        "\nExamples:\n"
        + HelpExampleCli("sm2getciphertext", "\"plaintext\",\"transcode\" ")
        + HelpExampleRpc("sm2getciphertext", "\"plaintext\",\"transcode\" ")
         );
    }
   
     StruCrypto *struCrypto = new StruCrypto;
     ClassSM2 classSM2;
     UniValue result(UniValue::VOBJ);
     int ret = -1;
     JudgeInputParameters *judgeInputPara = new JudgeInputParameters;
     //1 sm2
  
    struCrypto->strPlaintext = request.params[0].get_str();
    struCrypto->strTranscode = "hex";  
    if(2 == request.params.size())
    {
        struCrypto->strTranscode = request.params[1].get_str();
    }
    
    /*judge input parameters*/
    judgeInputPara->JudgeSM2Enc(struCrypto);


    struCrypto->strAlgorithm = "sm2";
    if (0 == struCrypto->strAlgorithm.compare("SM2") || 0 == struCrypto->strAlgorithm.compare("sm2") )
    {
        StruSM2Context *struContext = new StruSM2Context;
        memset(struContext, 0, sizeof(struContext));

        /********
         * publicKey:
        *************/ 
        const char * strPubKeyTemp = "sm2publicKey.pem";
        struContext->cPubKey = new unsigned char[MSG_LEN];
        memset(struContext->cPubKey, 0, MSG_LEN);
        memcpy((char *) struContext->cPubKey, strPubKeyTemp, strlen(strPubKeyTemp));
        struContext->strPubKey = (char *) struContext->cPubKey;
        
        //3 plaintext
        struContext->cPlaintextIn = new unsigned char[MSG_LEN];
        memset(struContext->cPlaintextIn, 0, MSG_LEN);
        struContext->iPlaintextLenIn = 0;
        memcpy(struContext->cPlaintextIn, struCrypto->strPlaintext.c_str(), strlen((char *) struCrypto->strPlaintext.c_str()) );
        struContext->iPlaintextLenIn = struCrypto->strPlaintext.length();
        LogPrintf("struContext->iPlaintextLenIn = %d, struContext->cPlaintextIn = %s\n", struContext->iPlaintextLenIn, struContext->cPlaintextIn);
       
        struContext->cCiphertextOut = new unsigned char[MSG_LEN_TRANSCODE];
        memset(struContext->cCiphertextOut, 0, MSG_LEN_TRANSCODE);
        struContext->iCiphertextLenOut = 0;

        ret = classSM2.SM2_Enc(struContext);
        if( ret < 0)
		{
			 cout <<"SM2_Enc doesn't successfully encrypt." <<endl;
             LogPrintf("SM2_Enc doesn't successfully encrypt.\n");
             throw JSONRPCError(SM2_ENC_ERROR, "SM2_Enc doesn't successfully encrypt.");   
             //return -1;      
        }	

           //编码
        if( 0 == struCrypto->strTranscode.compare("BASE64") || 0 == struCrypto->strTranscode.compare("base64"))
        {
            
            Base64 *base64 = new Base64();
            string *strCipherToBase64 = new string[MSG_LEN_TRANSCODE];  
            memset(strCipherToBase64, 0, MSG_LEN_TRANSCODE);  
            size_t strCipherToBase64Len = 0;
            strCipherToBase64Len = base64->Base64Encode(struContext->cCiphertextOut, (int) struContext->iCiphertextLenOut, strCipherToBase64);                  
            if(strCipherToBase64Len <= 0)
            {
                cout <<"The base64 doesn't encode at sm2getciphertext. "<<endl;
                LogPrintf("The base64 doesn't encode at sm2getciphertext. \n");
                throw JSONRPCError(BASE64_ENCODE_ERROR, " The base64 doesn't encode at sm2getciphertext. ");
            }
            
            cout<<"base64 encode :strCipherToBase64Len = "<< strCipherToBase64Len<<", *strCipherToBase64="<< *strCipherToBase64<<endl;
            LogPrintf("base64 encode :strCipherToBase64Len = %d ,  *strCipherToBase64= %s. \n",strCipherToBase64Len, strCipherToBase64);

          //  result.push_back(Pair("result", "the sm2 successfully encrypt."));
            result.push_back(Pair("transcode", struCrypto->strTranscode));
            result.push_back(Pair("ciphertextLen", strCipherToBase64Len));
            result.push_back(Pair("ciphertext", *strCipherToBase64));

            delete[] strCipherToBase64;
            delete base64;
        }
        else if( 0 == struCrypto->strTranscode.compare("BASE58") || 0 == struCrypto->strTranscode.compare("base58"))
        {
            Base58 *base58 = new Base58();
            string *strCipherToBase58 = new string[MSG_LEN_TRANSCODE];   
            memset(strCipherToBase58, 0, MSG_LEN_TRANSCODE); 
            size_t strCipherToBase58Len = 0;
            strCipherToBase58Len =  base58->Base58Encode(struContext->cCiphertextOut, (int) struContext->iCiphertextLenOut, strCipherToBase58);                  
            if(strCipherToBase58Len <= 0)
            {
                cout <<"The base58 doesn't encode at sm2getciphertext."<<endl;
                LogPrintf("The base58 doesn't encode at sm2getciphertext. \n");
                throw JSONRPCError(BASE58_ENCODE_ERROR, " The base58 doesn't encode at sm2getciphertext. ");
                //return -1;
            }  
            cout<<"base58 encode : strCipherToBase58Len= "<< strCipherToBase58Len<<", *strCipherToBase58="<< *strCipherToBase58<<endl;
            LogPrintf("base58 encode :strCipherToBase58Len = %d ,  *strCipherToBase58= %s. \n",strCipherToBase58Len, strCipherToBase58);

           // result.push_back(Pair("result", "the sm2 successfully encrypt."));
            result.push_back(Pair("transcode", struCrypto->strTranscode));
            result.push_back(Pair("ciphertextLen", strCipherToBase58Len));
            result.push_back(Pair("ciphertext", *strCipherToBase58));

            delete[] strCipherToBase58;
            delete base58;
        }
        else if( 0 == struCrypto->strTranscode.compare("HEX") || 0 == struCrypto->strTranscode.compare("hex"))
        {
            HexTranscode *hexTranscode = new HexTranscode();
            string *strCipherToHex = new string[MSG_LEN_TRANSCODE];  
            memset(strCipherToHex, 0,  MSG_LEN_TRANSCODE);  
            size_t strCipherToHexLen = 0;
            strCipherToHexLen = hexTranscode->HexEncode(struContext->cCiphertextOut, (int) struContext->iCiphertextLenOut, strCipherToHex);                  
            if(strCipherToHexLen <= 0)
            {
                cout <<"The hex is doesn't encode at sm2getciphertext."<<endl;
                LogPrintf("The hex is doesn't encode at sm2getciphertext.\n");
                throw JSONRPCError(HEX_ENCODE_ERROR, " The hex is doesn't encode at sm2getciphertext. ");
                //return -1;
            }  
            cout<<"hex encode : strCipherToHexLen= "<< strCipherToHexLen<<", *strCipherToHex="<< *strCipherToHex<<endl;
            LogPrintf("hex encode :strCipherToHexLen = %d ,  *strCipherToHex= %s. \n",strCipherToHexLen, strCipherToHex);
         
         //   result.push_back(Pair("result", "the sm2 successfully encrypt."));
            result.push_back(Pair("transcode", struCrypto->strTranscode));
            result.push_back(Pair("ciphertextLen", strCipherToHexLen));
            result.push_back(Pair("ciphertext", *strCipherToHex));

            delete[] strCipherToHex;
            delete hexTranscode;
        }
        else
        {
            cout <<"  The transcode is not encode to base64 、 base58 or hex  at sm2getciphertext."<<endl;
            LogPrintf("The transcode is not encode to base64 、 base58 or hex  at sm2getciphertext.\n");
            throw JSONRPCError(TRANSCODE_ERROR, "The transcode is not encode to base64 、 base58 or hex  at sm2getciphertext.");
            //return -1;
        }
     
     
        delete[] struContext->cPubKey;
        delete[] struContext->cPlaintextIn;
        delete[] struContext->cCiphertextOut;
        delete struContext;
        delete struCrypto;
        delete judgeInputPara;
       
   } 
    else
	{
		cout << "The algorithm is not SM2  at sm2getciphertext." <<endl;
        LogPrintf("The algorithm is not SM2  at sm2getciphertext.\n");
        throw JSONRPCError(SM2_ERROR, "The algorithm is not SM2  at sm2getciphertext.");
		//return -1;
	}
    return result;
}



/*******************************************************************************
* 1 SM2
* 函数介绍: *1.3 sm2recoverplaintext()：SM2解密函数
* 输入参数：json ciphertext ：密文 
           json transcode ：转码方式--base64/base58/16进制转码
           json decrypt or encrypt:解密或加密
* 输出参数: string  transcode：转码方式--base64/base58/16进制编码
           int strPlainOutLen ：输出SM2解密后的明文的长度
           string* strPlainOut：输出SM2解密后的明文
          
* 返 回 值: 0: 成功         != 0: 失败
注意：默认使用私钥sm2privateKey.pem
*******************************************************************************/
UniValue sm2recoverplaintext(const JSONRPCRequest& request)
{
    
    if (request.fHelp ||  request.params.size() < 1 || request.params.size() > 2)
    {
        throw runtime_error(
        "sm2recoverplaintext \n"
        "\nReturns  plaintext  recovered from ciphertext  by private key.\n"
        "\nArguments:\n"
        "1. \"ciphertext \"    (string, required) The ciphertext is the input data.\n"
        "2. \"transcode\"     (string, optional)The transcode is base64/hex,hex is setted as default parameter.\n"  
        //"3. \"decrypt \"     (string, optional)This is decrypt or encrypt,decrypt is setted as default parameter.\n"  
        "\nResult:\n"
        "{                        (json object)\n"   
     //   "  \"result\"             (string, The sm2 successfully decrypt. )\n"
        "  \"transcode\"           (string, This is the decode . )\n"
        "  \"plaintextLen \"   (string, This is the length of plaintext . )\n"
        "  \"plaintext\"      (string, The plaintext recovered from ciphertext  by private key\n"
        "}\n"
        "\nExamples:\n"
        + HelpExampleCli("sm2recoverplaintext", "\"ciphertext\",\"transcode\" ")
        + HelpExampleRpc("sm2recoverplaintext", "\"ciphertext\",\"transcode\" ")
         );
    }
   
     StruCrypto *struCrypto = new StruCrypto;
     ClassSM2 classSM2;
     UniValue result(UniValue::VOBJ);
     int ret = -1;
     JudgeInputParameters *judgeInputPara = new JudgeInputParameters;
     //1 sm2
      
    //struCrypto->strPrivKey = request.params[2].get_str();
    struCrypto->strCiphertext = request.params[0].get_str();
    struCrypto->strTranscode = "hex";
    if(2 == request.params.size())
    {
        struCrypto->strTranscode = request.params[1].get_str();
    }

    /*judge input parameters*/
    judgeInputPara->JudgeSM2Dec(struCrypto);

    struCrypto->strAlgorithm = "sm2";
    if (0 == struCrypto->strAlgorithm.compare("SM2") || 0 == struCrypto->strAlgorithm.compare("sm2") )
    {
        StruSM2Context *struContext = new StruSM2Context;
        memset(struContext, 0, sizeof(struContext));
        
        /****2 privateKey*/
        const char * strPrivKeyTemp = "sm2privateKey.pem";
        struContext->cPrivKey = new unsigned char[MSG_LEN];
        memset(struContext->cPrivKey, 0, MSG_LEN);
        memcpy((char *) struContext->cPrivKey, strPrivKeyTemp, strlen(strPrivKeyTemp));
        struContext->strPrivKey = (char *) struContext->cPrivKey;
      
        //3 ciphertext   
        struContext->cCiphertextIn = new unsigned char[MSG_LEN_TRANSCODE];
        memset(struContext->cCiphertextIn, 0, MSG_LEN_TRANSCODE);
        struContext->iCiphertextLenIn = 0;  
        //解码
        if( 0 == struCrypto->strTranscode.compare("BASE64") || 0 == struCrypto->strTranscode.compare("base64"))
        {
        
            Base64 *base64 = new Base64(); 
            struContext->iCiphertextLenIn = base64->Base64Decode(&struCrypto->strCiphertext, struCrypto->strCiphertext.length(), struContext->cCiphertextIn);
            if(struContext->iCiphertextLenIn <= 0 )
            {
                cout <<"The base64 doesn't decode at sm2recoverplaintext. "<<endl;
                LogPrintf("The base64 doesn't decode at sm2recoverplaintext.\n");
                throw JSONRPCError(BASE64_DECODE_ERROR, "The base64 doesn't decode  at sm2recoverplaintext.");
                //return -1;
            } 
                   
            cout<<"base64 decode : struContext->iCiphertextLenIn= "<< struContext->iCiphertextLenIn<<", struContext->cCiphertextIn="<< struContext->cCiphertextIn<<endl;
            LogPrintf("base64 decode : struContext->iCiphertextLenIn= %d, struContext->cCiphertextIn=%u\n",struContext->iCiphertextLenIn , struContext->cCiphertextIn);
            delete base64;
            
        }
        else if( 0 == struCrypto->strTranscode.compare("BASE58") || 0 == struCrypto->strTranscode.compare("base58"))
        {
            Base58 *base58 = new Base58(); 
            struContext->iCiphertextLenIn = base58->Base58Decode(&struCrypto->strCiphertext, struCrypto->strCiphertext.length(), struContext->cCiphertextIn);
            if( struContext->iCiphertextLenIn <= 0 )
            {
                cout <<"The base58 doesn't decode  at sm2recoverplaintext."<<endl;
                LogPrintf("The base58 doesn't decode  at sm2recoverplaintext.\n");
                throw JSONRPCError(BASE58_DECODE_ERROR, "The base58 doesn't decode  at sm2recoverplaintext.");
                //return -1;
            }
           
                
            cout<<"base58 decode : struContext->iCiphertextLenIn= "<< struContext->iCiphertextLenIn<<", struContext->cCiphertextIn="<< struContext->cCiphertextIn<<endl;
            LogPrintf("base58 decode : struContext->iCiphertextLenIn= %d, struContext->cCiphertextIn=%u\n",struContext->iCiphertextLenIn , struContext->cCiphertextIn);   
            delete base58;
        }
        else if( 0 == struCrypto->strTranscode.compare("HEX") || 0 == struCrypto->strTranscode.compare("hex"))
        {
            HexTranscode *hexTranscode = new HexTranscode(); 
            struContext->iCiphertextLenIn =  hexTranscode->HexDecode(&struCrypto->strCiphertext, struCrypto->strCiphertext.length(), struContext->cCiphertextIn);
            if(struContext->iCiphertextLenIn <= 0 )
            {
                cout <<" The hex doesn't decode   at sm2recoverplaintext."<<endl;
                LogPrintf("The hex doesn't decode  at sm2recoverplaintext.\n");
                throw JSONRPCError(HEX_DECODE_ERROR, "The hex doesn't decode  at sm2recoverplaintext.");
            }  
             
            cout<<" hex decode :  struContext->iCiphertextLenIn =" << struContext->iCiphertextLenIn<<", struContext->cCiphertextIn= "<<struContext->cCiphertextIn<<endl;
            LogPrintf("hex decode : struContext->iCiphertextLenIn= %d, struContext->cCiphertextIn=%u\n",struContext->iCiphertextLenIn , struContext->cCiphertextIn);   
            delete hexTranscode;
        }
        else
        {
            cout <<"The transcode is not decode to base64 、 base58 or hex at sm2recoverplaintext."<<endl;
            LogPrintf("The transcode is not decode to base64 、 base58 or hex at sm2recoverplaintext.\n");
            throw JSONRPCError(TRANSCODE_ERROR, "The transcode is not decode to base64 、 base58 or hex at sm2recoverplaintext.");
            //return -1;
        }
        

        struContext->cPlaintextOut = new unsigned char[MSG_LEN_OUT];
        memset(struContext->cPlaintextOut, 0, MSG_LEN_OUT);
        struContext->iPlaintextLenOut = 0;  
        ret = classSM2.SM2_Dec(struContext);
        if(ret != 0)
        {
            cout <<"SM2_Dec  doesn't successfully decrypt." <<endl;
            LogPrintf("SM2_Dec  doesn't successfully decrypt.\n");
            throw JSONRPCError(SM2_DEC_ERROR, "SM2_Dec  doesn't successfully decrypt.");
            //return -1;
        }
        
      //  result.push_back(Pair("result", "The sm2 successfully decrypt."));
        result.push_back(Pair("transcode", struCrypto->strTranscode.c_str()));
        result.push_back(Pair("plaintextLen", struContext->iPlaintextLenOut));
        result.push_back(Pair("plaintext", (char *)struContext->cPlaintextOut));

        delete[] struContext->cPrivKey;
        delete[] struContext->cCiphertextIn;
        delete[] struContext->cPlaintextOut;    
        delete struContext; 
        delete struCrypto;
        delete judgeInputPara;
    } 
    else
	{
		cout << " The algorithm is not SM2 at sm2recoverplaintext." <<endl;
        LogPrintf(" The algorithm is not SM2 at sm2recoverplaintext.\n");
        throw JSONRPCError(SM2_ERROR, " The algorithm is not SM2 at sm2recoverplaintext.");
		//return -1;
	}
    return result;
}

/*******************************************************************************
* 1 SM2
* 函数介绍: *1.4 sm2getsignatureinfo()：SM2签名函数
* 输入参数：json plaintext ： 明文
           json transcode ：转码方式--base64/base58/16进制转码
           
* 输出参数: string  transcode：转码方式--base64/base58/16进制编码
           int strPlainOutLen ：输出SM2解密后的明文解码长度
           string* strPlainOut：输出SM2解密后的明文解码值
          
* 返 回 值: 0: 成功         != 0: 失败
注意：默认使用私钥sm2privateKey.pem
*******************************************************************************/
UniValue sm2getsignatureinfo(const JSONRPCRequest& request)
{
    
    if (request.fHelp || request.params.size() < 1|| request.params.size() > 2)
    {
        throw runtime_error(
        "sm2getsignatureinfo\n"
        "\nReturns  signature information encrypted from plaintext by private key.\n"
        "\nArguments:\n"
        "1. \"plaintext\"     (string, required) The plaintext is the input data.\n"
        "2. \"transcode\"     (string, optional)The transcode is base64/hex,hex is setted as default parameter.\n"         
         "\nResult:\n"
        "{                      (json object)\n"   
      //  "  \"result\"         (string, The sm2 successfully signature. )\n"
        "  \"transcode\"      (string, This is the encode . )\n"
        "  \"signatureInfoLen\"   (string, This is the length of signature information. )\n"
        "  \"signatureInfo\"      (string, The signature information encrypted from plaintext by private key.\n"
        "}\n"
        "\nExamples:\n"
        + HelpExampleCli("sm2getsignatureinfo", "\"plaintext\",\"transcode\" ")
        + HelpExampleRpc("sm2getsignatureinfo", "\"plaintext\",\"transcode\" ")
         );
    }
   
     StruCrypto *struCrypto = new StruCrypto;
     ClassSM2 classSM2;
     UniValue result(UniValue::VOBJ);
     int ret = -1;
     JudgeInputParameters *judgeInputPara = new JudgeInputParameters;
     //1 sm2
   
   // struCrypto->strPrivKey = request.params[2].get_str();
    struCrypto->strPlaintext = request.params[0].get_str();
    struCrypto->strTranscode = "hex";
    if(2 == request.params.size())
    {
        struCrypto->strTranscode = request.params[1].get_str();
    }
    
     /*judge input parameters*/
    judgeInputPara->JudgeSM2Sig(struCrypto);
    

    struCrypto->strAlgorithm = "sm2";
    if (0 == struCrypto->strAlgorithm.compare("SM2") || 0 == struCrypto->strAlgorithm.compare("sm2") )
    {
        StruSM2Context *struContext = new StruSM2Context;
        memset(struContext, 0, sizeof(struContext));
        //2privatekey
        //struContext->strPrivKey =  struCrypto->strPrivKey.c_str();
        const char * strPrivKeyTemp = "sm2privateKey.pem";
        struContext->cPrivKey = new unsigned char[MSG_LEN];
        memset(struContext->cPrivKey, 0, MSG_LEN);
        memcpy((char *) struContext->cPrivKey, strPrivKeyTemp, strlen(strPrivKeyTemp));
        struContext->strPrivKey = (char *) struContext->cPrivKey;

        //3 plaintext
        struContext->cPlaintextIn = new unsigned char[MSG_LEN];
        memset(struContext->cPlaintextIn, 0, MSG_LEN);
        struContext->iPlaintextLenIn = 0;

        struCrypto->strPlaintext += '\n';
        memcpy(struContext->cPlaintextIn, struCrypto->strPlaintext.c_str(), struCrypto->strPlaintext.length()  );
        struContext->iPlaintextLenIn = struCrypto->strPlaintext.length();

        struContext->cSigInfo = new unsigned char[MSG_LEN_TRANSCODE];
        memset(struContext->cSigInfo, 0, MSG_LEN_TRANSCODE);
        struContext->iSigInfoLen = 0;
        ret = classSM2.SM2_Sig(struContext);
        if(ret < 0)
        {
            cout <<" SM2_Sig  doesn't successfully signature." <<endl;
            LogPrintf(" SM2_Sig  doesn't successfully signature.\n");
            throw JSONRPCError(SM2_SIG_ERROR, " SM2_Sig  doesn't successfully signature.");
            //return -1;
        }	

         //编码
        if( 0 == struCrypto->strTranscode.compare("BASE64") || 0 == struCrypto->strTranscode.compare("base64"))
        {
            
            Base64 *base64 = new Base64();
            string *strDigestToBase64 = new string[MSG_LEN_TRANSCODE];  
            memset(strDigestToBase64, 0, MSG_LEN_TRANSCODE);  
            size_t strDigestToBase64Len = 0;
            strDigestToBase64Len = base64->Base64Encode(struContext->cSigInfo, (int) struContext->iSigInfoLen, strDigestToBase64);                  
            if(strDigestToBase64Len <= 0)
            {
                cout <<"The base64 doesn't encode  at sm2getsignatureinfo. "<<endl;
                LogPrintf("The base64 doesn't encode  at sm2getsignatureinfo. \n");
                throw JSONRPCError(BASE64_ENCODE_ERROR, " The base64 doesn't encode  at sm2getsignatureinfo. ");
                //return -1;
            }
            cout<<"base64 encode :strDigestToBase64Len = "<< strDigestToBase64Len<<", *strDigestToBase64="<< *strDigestToBase64<<endl;
            LogPrintf("base64 encode :strDigestToBase64Len =%d, *strDigestToBase64=%s\n", strDigestToBase64Len, *strDigestToBase64);
          //  result.push_back(Pair("result", "the sm2 successfully digest."));
            result.push_back(Pair("transcode", struCrypto->strTranscode));
            result.push_back(Pair("signatureInfoLen", strDigestToBase64Len));
            result.push_back(Pair("signatureInfo", *strDigestToBase64));

            delete[] strDigestToBase64;
            delete base64;
        }
        else if( 0 == struCrypto->strTranscode.compare("BASE58") || 0 == struCrypto->strTranscode.compare("base58"))
        {
            Base58 *base58 = new Base58();
            string *strDigestToBase58 = new string[MSG_LEN_TRANSCODE];   
            memset(strDigestToBase58, 0, MSG_LEN_TRANSCODE); 
            size_t strDigestToBase58Len = 0;
            strDigestToBase58Len =  base58->Base58Encode(struContext->cSigInfo, (int) struContext->iSigInfoLen, strDigestToBase58);                  
            if(strDigestToBase58Len <= 0)
            {
                cout <<" The base58 doesn't encode at sm2getsignatureinfo."<<endl;
                LogPrintf(" The base58 doesn't encode at sm2getsignatureinfo. \n");
                throw JSONRPCError(BASE58_ENCODE_ERROR, " The base58 doesn't encode at sm2getsignatureinfo. ");
                //return -1;
            }  
            cout<<"base58 encode : strDigestToBase58Len= "<< strDigestToBase58Len<<", *strDigestToBase58="<< *strDigestToBase58<<endl;
            LogPrintf("base58 encode :strDigestToBase58Len =%d, *strDigestToBase58=%s\n", strDigestToBase58Len, *strDigestToBase58);
         //   result.push_back(Pair("result", "the sm2 successfully digest."));
            result.push_back(Pair("transcode", struCrypto->strTranscode));
            result.push_back(Pair("signatureInfoLen", strDigestToBase58Len));
            result.push_back(Pair("signatureInfo", *strDigestToBase58));

            delete[] strDigestToBase58;
            delete base58;
        }
        else if( 0 == struCrypto->strTranscode.compare("HEX") || 0 == struCrypto->strTranscode.compare("hex"))
        {
            HexTranscode *hexTranscode = new HexTranscode();
            string *strDigestToHex = new string[MSG_LEN_TRANSCODE];  
            memset(strDigestToHex, 0,  MSG_LEN_TRANSCODE);  
            size_t strDigestToHexLen = 0;
            strDigestToHexLen = hexTranscode->HexEncode(struContext->cSigInfo, (int) struContext->iSigInfoLen, strDigestToHex);                  
            if(strDigestToHexLen <= 0)
            {
                cout <<"The hex doesn't encode at sm2getsignatureinfo."<<endl;
                LogPrintf("The hex doesn't encode at sm2getsignatureinfo. \n");
                throw JSONRPCError(HEX_ENCODE_ERROR, " The hex doesn't encode at sm2getsignatureinfo. ");
                //return -1;
            }  
            cout<<"hex encode : strDigestToHexLen= "<< strDigestToHexLen<<", *strDigestToHex="<< *strDigestToHex<<endl;
            LogPrintf("hex encode :strDigestToHexLen =%d, *strDigestToHex=%s\n", strDigestToHexLen, *strDigestToHex);
         
          //  result.push_back(Pair("result", "the sm2 successfully digest."));
            result.push_back(Pair("transcode", struCrypto->strTranscode));
            result.push_back(Pair("signatureInfoLen", strDigestToHexLen));
            result.push_back(Pair("signatureInfo", *strDigestToHex));

            delete[]strDigestToHex;
            delete hexTranscode;
        }
        else
        {
            cout <<" The transcode is not encode to base64 、 base58 or hex at sm2getsignatureinfo."<<endl;
            LogPrintf("The transcode is not encode to base64 、 base58 or hex at sm2getsignatureinfo. \n");
            throw JSONRPCError(TRANSCODE_ERROR, "The transcode is not encode to base64 、 base58 or hex at sm2getsignatureinfo. ");
            //return -1;
        }
        
        delete[]  struContext->cPrivKey;
        delete[] struContext->cPlaintextIn;
        delete[] struContext->cSigInfo;
        delete struContext;  
        delete struCrypto;  
        delete judgeInputPara;
    } 
    else
	{
		cout << "The algorithm is not SM2 at sm2getsignatureinfo." <<endl;
        LogPrintf("The algorithm is not SM2 at sm2getsignatureinfo.\n");
        throw JSONRPCError(SM2_ERROR, "The algorithm is not SM2 at sm2getsignatureinfo.");
		//return -1;
	}
    return result;
}


/*******************************************************************************
* 1 SM2
* 函数介绍: *1.5 sm2getsignatureverify()：SM2验签函数
* 输入参数：json plaintext ： 明文
           json signature information:签名信息
           json transcode ：转码方式--base64/base58/16进制转码

* 输出参数: 
           verify:验证签名是否成功！
          
* 返 回 值: 0: 成功         != 0: 失败
注意：默认使用公钥sm2publicKey.pem
*******************************************************************************/
UniValue sm2getsignatureverify(const JSONRPCRequest& request)
{
    
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
    {
        throw runtime_error(
        "sm2getsignatureverify\n"
        "\nReturns signature verify  decrypted from plaintext by public key.\n"
        "\nArguments:\n"
        "1. \"plaintext\"                 (string, required) The plaintext is the input data.\n"
        "2. \"signature information\"     (string, required) The signature information is the input data.\n"
        "3. \"transcode\"                 (string, optional) The transcode is base64/hex, and hex is setted as default parameter..\n"      
        "\nResult:\n"
          " \"result\"         (string, The sm2 successfully verify decrypted from plaintext by public key. )\n"
        "\nExamples:\n"
        + HelpExampleCli("sm2getsignatureverify", "\"plaintext\",\"signature information\",\"transcode\" ")
        + HelpExampleRpc("sm2getsignatureverify", "\"plaintext\",\"signature information\",\"transcode\" ")
         );
    }
   
     StruCrypto *struCrypto = new StruCrypto;
     ClassSM2 classSM2;
     UniValue result(UniValue::VOBJ);
     int ret = -1;
     JudgeInputParameters *judgeInputPara = new JudgeInputParameters;
     //1 sm2
    
    //struCrypto->strPubKey    = request.params[2].get_str();
    struCrypto->strPlaintext = request.params[0].get_str();
    struCrypto->strSigInfo   = request.params[1].get_str();
    struCrypto->strTranscode = "hex";
    
    if(3 == request.params.size())
    {
        struCrypto->strTranscode = request.params[2].get_str();
    }

     /*judge input parameters*/
    judgeInputPara->JudgeSM2Ver(struCrypto);

    struCrypto->strAlgorithm = "sm2";
    if (0 == struCrypto->strAlgorithm.compare("SM2") || 0 == struCrypto->strAlgorithm.compare("sm2") )
    {
        StruSM2Context *struContext = new StruSM2Context;
        memset(struContext, 0, sizeof(struContext));

        //publickey
        const char * strPubKeyTemp = "sm2publicKey.pem";
        struContext->cPubKey = new unsigned char[MSG_LEN];
        memset(struContext->cPubKey, 0, MSG_LEN);
        memcpy((char *) struContext->cPubKey, strPubKeyTemp, strlen(strPubKeyTemp));
        struContext->strPubKey = (char *) struContext->cPubKey;

        //明文
        struContext->cPlaintextIn = new unsigned char[MSG_LEN];
        memset(struContext->cPlaintextIn, 0, MSG_LEN);
        struContext->iPlaintextLenIn = 0;
        struCrypto->strPlaintext += '\n';
        memcpy(struContext->cPlaintextIn, struCrypto->strPlaintext.c_str(), struCrypto->strPlaintext.length());
        struContext->iPlaintextLenIn = struCrypto->strPlaintext.length();
 
        //签名信息
        struContext->cSigInfo = new unsigned char[MSG_LEN_TRANSCODE];
        memset(struContext->cSigInfo, 0, MSG_LEN_TRANSCODE);
        struContext->iSigInfoLen = 0;
         //签名信息解码
        if( 0 == struCrypto->strTranscode.compare("BASE64") || 0 == struCrypto->strTranscode.compare("base64"))
        {
        
            Base64 *base64 = new Base64(); 
            struContext->iSigInfoLen = base64->Base64Decode(&struCrypto->strSigInfo, struCrypto->strSigInfo.length() , struContext->cSigInfo);
            if(struContext->iSigInfoLen <= 0 )
            {
                cout <<"The base64 doesn't decode at sm2getsignatureverify. "<<endl;
                LogPrintf("The base64 doesn't decode at sm2getsignatureverify.\n");
                throw JSONRPCError(BASE64_DECODE_ERROR, " The base64 doesn't decode at sm2getsignatureverify.");  
                //return -1;
            }
                        
            cout<<"base64 decode : struContext->iSigInfoLen= "<< struContext->iSigInfoLen<<", struContext->cSigInfo="<< struContext->cSigInfo<<endl;
            LogPrintf("base64 decode : struContext->iSigInfoLen= %d, struContext->cSigInfo=%u \n", struContext->iSigInfoLen,struContext->cSigInfo);
            delete base64;
            
        }
        else if( 0 == struCrypto->strTranscode.compare("BASE58") || 0 == struCrypto->strTranscode.compare("base58"))
        {
            Base58 *base58 = new Base58(); 
            struContext->iSigInfoLen = base58->Base58Decode(&struCrypto->strSigInfo, struCrypto->strSigInfo.length(), struContext->cSigInfo);
            if( struContext->iSigInfoLen <= 0 )
            {
                cout <<"The base58 doesn't decode at sm2getsignatureverify."<<endl;
                LogPrintf("The base58 doesn't decode at sm2getsignatureverify.\n");
                throw JSONRPCError(BASE58_DECODE_ERROR, "The base58 doesn't decode at sm2getsignatureverify.");  
                //return -1;
            }
                
            cout<<"base58 decode : struContext->iSigInfoLen= "<< struContext->iSigInfoLen<<", struContext->cSigInfo="<< struContext->cSigInfo<<endl;
            LogPrintf("base58 decode : struContext->iSigInfoLen= %d, struContext->cSigInfo=%u \n", struContext->iSigInfoLen,struContext->cSigInfo);
            delete base58;
        }
        else if( 0 == struCrypto->strTranscode.compare("HEX") || 0 == struCrypto->strTranscode.compare("hex"))
        {
            HexTranscode *hexTranscode = new HexTranscode(); 
            struContext->iSigInfoLen =  hexTranscode->HexDecode(&struCrypto->strSigInfo, struCrypto->strSigInfo.length(), struContext->cSigInfo);
            if(struContext->iSigInfoLen <= 0 )
            {
                cout <<"The hex doesn't decode at sm2getsignatureverify."<<endl;
                LogPrintf("The hex doesn't decode at sm2getsignatureverify\n");
                throw JSONRPCError(HEX_DECODE_ERROR, "The hex doesn't decode at sm2getsignatureverify.");  
                //return -1;
            }     

            cout<<" hex decode : struContext->iSigInfoLen =" << struContext->iSigInfoLen<<", struContext->cSigInfo= "<<struContext->cSigInfo<<endl;
            LogPrintf("hex decode : struContext->iSigInfoLen= %d, struContext->cSigInfo=%u \n", struContext->iSigInfoLen,struContext->cSigInfo);
        
           delete hexTranscode;
        }
        else
        {
            cout <<" The transcode is not decode to base64 、 base58 or hex  at sm2getsignatureverify."<<endl;
            LogPrintf("The transcode is not decode to base64 、 base58 or hex  at sm2getsignatureverify.\n");
            throw JSONRPCError(TRANSCODE_ERROR, "The transcode is not decode to base64 、 base58 or hex  at sm2getsignatureverify.");  
            //return -1;
        }
    
        ret = classSM2.SM2_Ver(struContext);
        if(ret < 0)
        {
            cout <<"SM2_Ver doesn't  successfully verify." <<endl;
            LogPrintf("SM2_Ver doesn't  successfully verify.\n");
            throw JSONRPCError(SM2_VER_ERROR, "SM2_Ver doesn't  successfully verify."); 
            //return -1;
        }

        result.push_back(Pair("result", "The sm2 successfully verify."));    

        delete[] struContext->cPubKey;    
        delete[] struContext->cPlaintextIn;
        delete[] struContext->cSigInfo;
        delete struContext;
        delete struCrypto;   
        delete judgeInputPara;
    } 
    else
	{
		cout << " The algorithm is not SM2 at sm2getsignatureverify." <<endl;
        LogPrintf(" The algorithm is not SM2 at sm2getsignatureverify.\n");
        throw JSONRPCError(SM2_ERROR, " The algorithm is not SM2 at sm2getsignatureverify."); 
		//return -1;
	}
    return result;
}


/*******************************************************************************
* 2 SM3
* 函数介绍: * sm3getdigest()：SM3消息摘要函数
* 输入参数：json plaintext ：明文
           json transcode ：转码方式--base64/base58/16进制转码
          
* 输出参数: string  transcode：转码方式--base64/base58/16进制转码
           int strDigestOut ：转码后的消息摘要长度
           string* strDigestOut：转码后的消息摘要
          
* 返 回 值: 0: 成功         <0: 失败
*******************************************************************************/
UniValue sm3getdigest(const JSONRPCRequest& request)
{
    
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
    {
        throw runtime_error(
        "sm3getdigest\n"
        "\nReturns  digest hashed from plaintext.\n"
        "\nArguments:\n"
        "1. \"plaintext\"     (string, required) The plaintext is input data.\n"
        "2. \"transcode\"     (string, optional)The transcode is base64/hex, and hex is setted as default parameter..\n"   
        "\nResult:.\n"
        "{                      (json object)\n"   
       // "  \"result\"         (string, The sm3 successfully digest. )\n"
        "  \"transcode\"      (string, This is the encode . )\n"
        "  \"digestLen\"   (string, This is the length of digest. )\n"
        "  \"digest\"      (string, The digest  hashed from plaintext.)\n"
        "}\n"
        "\nExamples:\n"
        + HelpExampleCli("sm3getdigest", "\"plaintext\",\"transcode\" ")
        + HelpExampleRpc("sm3getdigest", "\"plaintext\",\"transcode\" ")
         );
    }
    
     StruCrypto *struCrypto = new StruCrypto;
     ClassSM3 classSM3;
     UniValue valRequest;
     UniValue result(UniValue::VOBJ);
     int ret = -1;
     JudgeInputParameters *judgeInputPara = new JudgeInputParameters;
     
    struCrypto->strPlaintext = request.params[0].get_str();
    struCrypto->strTranscode = "hex";
    
    if(2 == request.params.size())
    {
        struCrypto->strTranscode = request.params[1].get_str();
    }
     
     /*judge input parameters*/
    judgeInputPara->JudgeSM3Dig(struCrypto);

    struCrypto->strAlgorithm = "sm3";
    if (0 == struCrypto->strAlgorithm.compare("SM3") || 0 == struCrypto->strAlgorithm.compare("sm3") )
    {
        StruContext *struContext = new StruContext;
		memset(struContext, 0, sizeof(struContext));

        struContext->cPlaintextIn = new unsigned char[MSG_LEN];
        memset( struContext->cPlaintextIn, 0, MSG_LEN);
        struContext->iPlaintextLenIn = 0;

        #if 0
        if( 0 == struCrypto->strTranscode.compare("HEX") || 0 == struCrypto->strTranscode.compare("hex"))
        {
            HexTranscode *hexTranscode = new HexTranscode(); 
            struCrypto->strPlaintext += "0A"; //追加换行符'\n'：16进制的"0A
            struContext->iPlaintextLenIn =  hexTranscode->HexDecode(&struCrypto->strPlaintext, struCrypto->strPlaintext.length(), struContext->cPlaintextIn);
            if(struContext->iPlaintextLenIn <= 0 )
            {
                cout <<"The hex doesn't decode  at sm3getdigest. "<<endl;
                LogPrintf("The hex doesn't decode  at sm3getdigest.\n");
                throw JSONRPCError(HEX_DECODE_ERROR, "The hex doesn't decode  at sm3getdigest."); 
            }  
            cout<<" struContext->iPlaintextLenIn = "<< struContext->iPlaintextLenIn <<", struContext->cPlaintextIn="<<struContext->cPlaintextIn<<endl;
            delete hexTranscode;
        }
        else
        {
            struCrypto->strPlaintext += '\n'; //追加换行符'\n' 
            memcpy(struContext->cPlaintextIn, (char *) struCrypto->strPlaintext.c_str(), strlen((char *) struCrypto->strPlaintext.c_str()) + 1);
            struContext->iPlaintextLenIn = strlen((char *)struContext->cPlaintextIn);
            cout<<" struContext->iPlaintextLenIn = "<< struContext->iPlaintextLenIn <<", struContext->cPlaintextIn="<<struContext->cPlaintextIn<<endl;
          
        }
        #endif
        

        struCrypto->strPlaintext += '\n'; //追加换行符'\n' 
        memcpy(struContext->cPlaintextIn, (char *) struCrypto->strPlaintext.c_str(), strlen((char *) struCrypto->strPlaintext.c_str()) + 1);
        struContext->iPlaintextLenIn = strlen((char *)struContext->cPlaintextIn);
        cout<<" struContext->iPlaintextLenIn = "<< struContext->iPlaintextLenIn <<", struContext->cPlaintextIn="<<struContext->cPlaintextIn<<endl;
        
               
        struContext->cDigestOut = new unsigned char[MSG_LEN_TRANSCODE];
        memset( struContext->cDigestOut, 0, MSG_LEN_TRANSCODE);
        struContext->iDigestLenOut = 0;
        ret = classSM3.SM3_Digest_Algorithm(struContext);
		if(ret != 0)
		{
			cout <<"SM3_Digest_Algorithm is error!" <<endl;
            LogPrintf("SM3_Digest_Algorithm is error.\n");
            throw JSONRPCError(SM3_DIG_ERROR, "SM3_Digest_Algorithm is error.");  			
		}	
  
          //编码
        if( 0 == struCrypto->strTranscode.compare("BASE64") || 0 == struCrypto->strTranscode.compare("base64"))
        {
            Base64 *base64 = new Base64();
            string *strDigestToBase64  = new string[MSG_LEN_TRANSCODE]; 
            memset(strDigestToBase64, 0, MSG_LEN_TRANSCODE);   
            size_t strDigestToBase64Len = 0;
            strDigestToBase64Len = base64->Base64Encode(struContext->cDigestOut, (int) struContext->iDigestLenOut, strDigestToBase64);                  
            if(strDigestToBase64Len <= 0)
            {
                cout <<"The base64 doesn't encode at sm3getdigest. "<<endl;
                LogPrintf("The base64 doesn't encode at sm3getdigest .\n");
                throw JSONRPCError(BASE64_ENCODE_ERROR, " The base64 doesn't encode at sm3getdigest.");  
               
            }
            cout<<"base64 encode :strDigestToBase64Len = "<< strDigestToBase64Len<<", *strDigestToBase64="<< *strDigestToBase64<<endl;
            LogPrintf("base64 encode :DigestLen = %d, Digest=%s\n",strDigestToBase64Len, *strDigestToBase64);

          //  result.push_back(Pair("result", "the sm3 successfully digest."));
            result.push_back(Pair("transcode", struCrypto->strTranscode));
            result.push_back(Pair("DigestLen", strDigestToBase64Len));
            result.push_back(Pair("Digest", *strDigestToBase64));
            delete[] strDigestToBase64;
            delete base64;
        }
        else if( 0 == struCrypto->strTranscode.compare("BASE58") || 0 == struCrypto->strTranscode.compare("base58"))
        {
            Base58 *base58 = new Base58();
            string *strDigestToBase58 = new string[MSG_LEN_TRANSCODE]; 
            memset(strDigestToBase58, 0, MSG_LEN_TRANSCODE);   
            size_t strDigestToBase58Len = 0;
            strDigestToBase58Len =  base58->Base58Encode(struContext->cDigestOut, (int) struContext->iDigestLenOut, strDigestToBase58);                  
            if(strDigestToBase58Len <= 0)
            {
                cout <<"The base58 doesn't encode at sm3getdigest. "<<endl;
                LogPrintf("The base58 doesn't encode at sm3getdigest.\n");
                throw JSONRPCError(BASE58_ENCODE_ERROR, "The base58 doesn't encode at sm3getdigest.");  
                //return -1;
            }  
          
            cout<<"base58 encode : strDigestToBase58Len= "<< strDigestToBase58Len<<", *strDigestToBase58="<< *strDigestToBase58<<endl;
            LogPrintf("base58 encode :DigestLen = %d, Digest=%s\n",strDigestToBase58Len, *strDigestToBase58);

           // result.push_back(Pair("result", "the sm3 successfully digest."));
            result.push_back(Pair("transcode", struCrypto->strTranscode));
            result.push_back(Pair("digestLen", strDigestToBase58Len));
            result.push_back(Pair("digest", *strDigestToBase58));

            delete[] strDigestToBase58;
            delete base58;
        }
        else if( 0 == struCrypto->strTranscode.compare("HEX") || 0 == struCrypto->strTranscode.compare("hex"))
        {
            HexTranscode *hexTranscode = new HexTranscode();
            string *strDigestToHex = new string[MSG_LEN_TRANSCODE];    
            memset(strDigestToHex, 0, MSG_LEN_TRANSCODE);
            size_t strDigestToHexLen = 0;
            strDigestToHexLen = hexTranscode->HexEncode(struContext->cDigestOut, (int) struContext->iDigestLenOut, strDigestToHex);                  
            if(strDigestToHexLen <= 0)
            {
                cout <<"The hex doesn't encode at sm3getdigest."<<endl;
                LogPrintf("The hex doesn't encode at sm3getdigest.\n");
                throw JSONRPCError(HEX_ENCODE_ERROR, "The hex doesn't encode at sm3getdigest.");  
            }  
            cout<<"hex encode : strDigestToHexLen= "<< strDigestToHexLen<<", *strDigestToHex="<< *strDigestToHex<<endl;
            LogPrintf("hex encode :DigestLen = %d, Digest=%s\n",strDigestToHexLen, *strDigestToHex);

          //  result.push_back(Pair("result", "the sm3 successfully digest."));
            result.push_back(Pair("transcode", struCrypto->strTranscode));
            result.push_back(Pair("DigestLen", strDigestToHexLen));
            result.push_back(Pair("Digest", *strDigestToHex));
            delete[] strDigestToHex;
            delete hexTranscode;
        }
        else
        {
            cout <<"The transcode is not encode to base64 、 base58 or hex at sm3getdigest"<<endl;
            LogPrintf("The transcode is not encode to base64 、 base58 or hex at sm3getdigest\n");
            throw JSONRPCError(TRANSCODE_ERROR, "The transcode is not encode to base64 、 base58 or hex at sm3getdigest."); 
            //return -1;
        }
          
        delete[] struContext->cPlaintextIn;
        delete[] struContext->cDigestOut;
        delete struContext;
        delete struCrypto;
        delete judgeInputPara;
    } 
    else
	{
		cout << "The algorithm is not SM3 at sm3getdigest." <<endl;
        LogPrintf("The algorithm is not SM3 at sm3getdigest.\n");
        throw JSONRPCError(SM3_ERROR, "The algorithm is not SM3 at sm3getdigest.");  
	}

    return result;
}


/*******************************************************************************
* 3 SM4
* 函数介绍: * sm4getciphertext()：SM4加密函数
* 输入参数：json plaintext ：明文
           json key ：密钥
           json transcode ：转码方式--base64/base58/16进制转码
           json mode ：ecb、cbc模式
* 输出参数: string  transcode：转码方式--base64/base58/16进制转码
           int strCipherOutLen ：输出SM4加密后编码密文的长度
           string* strCipherOut：输出SM4加密后编码密文
          
* 返 回 值: 0: 成功         <0: 失败
*******************************************************************************/
UniValue sm4getciphertext(const JSONRPCRequest& request)
{
    
    if (request.fHelp || request.params.size() < 2 ||  request.params.size() > 4)
    {
        throw runtime_error(
        "sm4getciphertext\n"
        "\nReturns  ciphertext encrypted from plaintext by key.\n"
        "\nArguments:\n"
        "1. \"plaintext\"     (string, required) The plaintext is input data.\n"
        "2. \"key\"           (string, required) The length of sm4-key is 128 bits, which is hex or string.\n"
        "3. \"transcode\"     (string, optional)The transcode is base64/hex,and hex is setted as default parameter..\n"     
       // "4. \"mode\"          (string, optional) The mode is ecb or cbc,and ecb is setted as default parameter. \n"   
        "4. \"mode\"          (string, optional) The mode is ecb,and ecb is setted as default parameter. \n"     
        "\nResult:\n"
        "{                     (json object)\n"   
       // "  \"result\"          (string, The sm4 successfully encrypt. )\n"
        "  \"transcode\"       (string, This is the encode . )\n"
        "  \"mode\"            (string, This is the mode of encrypt. )\n"
        "  \"ciphertextLen\"   (string, This is the length of ciphertext. )\n"
        "  \"ciphertext\"      (string, The plaintext  encrypted from plaintext by key.)\n"
        "}\n"
        "\nExamples:\n"
        + HelpExampleCli("sm4getciphertext","\"plaintext\",\"key\",\"transcode\",\"mode\" ")
        + HelpExampleRpc("sm4getciphertext", "\"plaintext\",\"key\",\"transcode\",\"mode\" ")
         );
    }
    

     StruCrypto *struCrypto = new StruCrypto;
     ClassSM4 classSM4;
     UniValue valRequest;
     UniValue result(UniValue::VOBJ);
     int ret = -1;
     JudgeInputParameters *judgeInputPara = new JudgeInputParameters;
     
    struCrypto->strPlaintext = request.params[0].get_str(); 
    struCrypto->strKey = request.params[1].get_str(); 
    struCrypto->strTranscode = "hex";
    struCrypto->strMode = "ecb";
    if(3 == request.params.size())
    {
        string strParamTemp = request.params[2].get_str();
        if(0 == strParamTemp.compare("ecb") || 0 == strParamTemp.compare("ECB") || 0 == strParamTemp.compare("cbc") 
            || 0 == strParamTemp.compare("CBC") )
        {
            struCrypto->strMode = request.params[2].get_str();
        }
        else
        {
            struCrypto->strTranscode = request.params[2].get_str();
        }
    }
    else if(4 == request.params.size())
    {
        struCrypto->strTranscode = request.params[2].get_str();
        struCrypto->strMode = request.params[3].get_str();
    }
    
    /*judge input parameters*/
    judgeInputPara->JudgeSM4Enc(struCrypto);
    
    struCrypto->strAlgorithm = "sm4";
    if (0 == struCrypto->strAlgorithm.compare("SM4") || 0 == struCrypto->strAlgorithm.compare("sm4") )
    {
        StruContext *struContext = new StruContext;
        memset(struContext, 0, sizeof(struContext));
        struContext->cMode = struCrypto->strMode.c_str();
      
        //key
        struContext->cKey = new unsigned char[SM4_KEY_LEN];
        memset(struContext->cKey, 0, SM4_KEY_LEN);
        struContext->iKeyLen = 0;
        if( 0 == struCrypto->strTranscode.compare("HEX") || 0 == struCrypto->strTranscode.compare("hex"))
        {
            HexTranscode *hexTranscode = new HexTranscode(); 
            struContext->iKeyLen =  hexTranscode->HexDecode(&struCrypto->strKey, struCrypto->strKey.length(), struContext->cKey);
            if(struContext->iKeyLen <= 0 )
            {
                cout <<"The hex doesn't decode  at sm4getciphertext. "<<endl;
                LogPrintf("The hex doesn't decode  at sm4getciphertext.\n");
                throw JSONRPCError(HEX_DECODE_ERROR, "The hex doesn't decode  at sm4getciphertext."); 
                //return -1;
            }
        
            cout<<" hex encode : struContext->iKeyLen =" << struContext->iKeyLen<<", struContext->cKey= "<<struContext->cKey<<endl;
            LogPrintf("hex encode :struContext->iKeyLen = %d,   struContext->cKey=%s.\n",struContext->iKeyLen,  struContext->cKey);
            delete hexTranscode;
        }
        else
        {
            memcpy(struContext->cKey,(char *) struCrypto->strKey.c_str(), struCrypto->strKey.length());
		    struContext->iKeyLen = struCrypto->strKey.length();
        }
        
    
        //palintext
        struContext->cPlaintextIn = new unsigned char[MSG_LEN];
        memset(struContext->cPlaintextIn, 0, MSG_LEN);
        struContext->iPlaintextLenIn = 0;
        memcpy(struContext->cPlaintextIn, struCrypto->strPlaintext.c_str(), struCrypto->strPlaintext.length());
        struContext->iPlaintextLenIn = struCrypto->strPlaintext.length();
        cout<<"struContext->iPlaintextLenIn="<<struContext->iPlaintextLenIn<<", struContext->cPlaintextIn= "<<(char *)struContext->cPlaintextIn<<endl;
      
        struContext->cCiphertextOut = new unsigned char[MSG_LEN_TRANSCODE];
		memset(struContext->cCiphertextOut, 0, MSG_LEN_TRANSCODE);
        struContext->iCiphertextLenOut = 0;
        ret = classSM4.SM4_Enc(struContext);
        if(ret != 0)
        {
            cout <<" The SM4_Enc doesn't successfully encrypt." <<endl;
            LogPrintf("The SM4_Enc doesn't successfully encrypt.\n");
            throw JSONRPCError(SM4_ENC_ERROR, "The SM4_Enc doesn't successfully encrypt.");
            //return -1;
        }      
    
         //编码
        if( 0 == struCrypto->strTranscode.compare("BASE64") || 0 == struCrypto->strTranscode.compare("base64"))
        {
            Base64 *base64 = new Base64();
            string *strCipherToBase64 = new string[MSG_LEN_TRANSCODE];  
            memset(strCipherToBase64, 0,  MSG_LEN_TRANSCODE);
            size_t strCipherToBase64Len = 0 ;
            strCipherToBase64Len = base64->Base64Encode(struContext->cCiphertextOut, (int) struContext->iCiphertextLenOut, strCipherToBase64);                  
            if(strCipherToBase64Len <= 0)
            {
                cout <<"The base64 doesn't encode at sm4getciphertext. "<<endl;
                LogPrintf("The base64 doesn't encode at sm4getciphertext.\n");
                throw JSONRPCError(BASE64_ENCODE_ERROR, " The base64 doesn't encode at sm4getciphertext.");
                //return -1;
            }
           
            cout<<"base64 encode :strCipherToBase64Len = "<< strCipherToBase64Len<<", *strCipherToBase64="<< *strCipherToBase64<<endl;
            LogPrintf("base64 encode :strCipherToBase64Len = %d,  *strCipherToBase64=%s.\n",strCipherToBase64Len, *strCipherToBase64);
           
          //  result.push_back(Pair("result", "the sm4 successfully encrypt."));
            result.push_back(Pair("transcode", struCrypto->strTranscode)); 
            result.push_back(Pair("mode", struCrypto->strMode));
            result.push_back(Pair("ciphertextLen", strCipherToBase64Len));
            result.push_back(Pair("ciphertext", *strCipherToBase64));
            
            delete[] strCipherToBase64;
            delete base64;
        }
        else if( 0 == struCrypto->strTranscode.compare("BASE58") || 0 == struCrypto->strTranscode.compare("base58"))
        {
            Base58 *base58 = new Base58();
            string *strCipherToBase58 = new string[MSG_LEN_TRANSCODE];  
            memset(strCipherToBase58, 0,  MSG_LEN_TRANSCODE);  
            size_t strCipherToBase58Len = 0;
            strCipherToBase58Len =  base58->Base58Encode(struContext->cCiphertextOut, (int) struContext->iCiphertextLenOut, strCipherToBase58);                  
            if(strCipherToBase58Len <= 0)
            {
                cout <<"The base58 doesn't encode at sm4getciphertext."<<endl;
                LogPrintf("The base58 doesn't encode at sm4getciphertext\n");
                throw JSONRPCError(BASE58_ENCODE_ERROR, "The base58 doesn't encode at sm4getciphertext.");
                //return -1;
            }  
            
            cout<<"base58 encode : strCipherToBase58Len= "<< strCipherToBase58Len<<", *strCipherToBase58="<< *strCipherToBase58<<endl;
            LogPrintf("base58 encode :strCipherToBase58Len = %d,  *strCipherToBase58=%s.\n",strCipherToBase58Len, *strCipherToBase58);
          
           // result.push_back(Pair("result", "the sm4 successfully encrypt."));
            result.push_back(Pair("transcode", struCrypto->strTranscode));
            result.push_back(Pair("mode", struCrypto->strMode));
            result.push_back(Pair("ciphertextLen", strCipherToBase58Len));
            result.push_back(Pair("ciphertext", *strCipherToBase58));

            delete[] strCipherToBase58;
            delete base58;
        }
        else if( 0 == struCrypto->strTranscode.compare("HEX") || 0 == struCrypto->strTranscode.compare("hex"))
        {
            HexTranscode *hexTranscode = new HexTranscode();
            string *strCipherToHex = new string[MSG_LEN_TRANSCODE]; 
            memset(strCipherToHex, 0,  MSG_LEN_TRANSCODE);     
            size_t strCipherToHexLen = 0;
         
            strCipherToHexLen = hexTranscode->HexEncode(struContext->cCiphertextOut, (int) struContext->iCiphertextLenOut, strCipherToHex);                  
            if(strCipherToHexLen <= 0)
            {
                cout <<"The hex doesn't encode at sm4getciphertext"<<endl;
                LogPrintf("The hex doesn't encode at sm4getciphertext\n");
                throw JSONRPCError(HEX_ENCODE_ERROR, "The hex doesn't encode at sm4getciphertext.");
                //return -1;
            }  
            
            cout<<"hex encode : strCipherToHexLen= "<< strCipherToHexLen<<", *strCipherToHex="<< *strCipherToHex<<endl;
            LogPrintf("hex encode :strCipherToHexLen = %d,  *strCipherToHex=%s.\n",strCipherToHexLen, *strCipherToHex);
          
            //result.push_back(Pair("result", "the sm4 successfully encrypt."));
            result.push_back(Pair("transcode", struCrypto->strTranscode));
            result.push_back(Pair("mode", struCrypto->strMode));
            result.push_back(Pair("ciphertextLen", strCipherToHexLen));
            result.push_back(Pair("ciphertext", *strCipherToHex));
            delete[] strCipherToHex;
            delete hexTranscode;
        }
        else
        {
            cout <<" The strTranscode is not encode to base64 、 base58 or hex at sm4getciphertext."<<endl;
            LogPrintf("The strTranscode is not encode to base64 、 base58 or hex at sm4getciphertext.\n");
            throw JSONRPCError(TRANSCODE_ERROR, "The strTranscode is not encode to base64 、 base58 or hex at sm4getciphertext.");
            //return -1;
        }
     
        delete[] struContext->cKey;
        delete[] struContext->cPlaintextIn;
        delete[] struContext->cCiphertextOut;
        delete struContext;
        delete struCrypto;
        delete judgeInputPara;
    }
    else
    {
        cout << "The algorithm is not SM4 at sm4getciphertext." <<endl;
        LogPrintf("The algorithm is not SM4 at sm4getciphertext.\n");
        throw JSONRPCError(SM4_ERROR, "The algorithm is not SM4 at sm4getciphertext.");  
    }
   
        
    return result;
}


/*******************************************************************************
* 1 SM4
* 函数介绍: *3.2 sm4recoverplaintext()：SM4解密函数
* 输入参数：json ciphertext ：明文
           json Key：密钥
           json transcode ：转码方式--base64/base58/16进制转码
           json mode : ecb、cbc模式
* 输出参数: string  transcode：转码方式--base64/base58/16进制编码
           int strPlainOutLen ：输出SM4解密后明文长度
           string* strPlainOut：输出SM4解密后明文
          
* 返 回 值: 0: 成功         != 0: 失败
*******************************************************************************/
UniValue sm4recoverplaintext(const JSONRPCRequest& request)
{
    
    if (request.fHelp ||request.params.size() < 2 || request.params.size() > 4)
    {
        throw runtime_error(
        "sm4recoverplaintext\n"
        "\nReturns  plaintext  decrypted from ciphertext by key.\n"
        "\nArguments:\n"
        "1. \"ciphertext\"    (string, required) The ciphertext is input data.\n"
        "2. \"key\"           (string, required) The length of sm4-key is 128 bits, which is hex or string.\n"
        //"3. \"transcode\"     (string, optional)The transcode is base64/hex,and hex is setted as default parameter..\n"     
        //"4. \"mode\"          (string, optional) The mode is ecb or cbc,and ecb is setted as default parameter. \n"
        "3. \"transcode\"     (string, optional)The transcode is base64/hex,and hex is setted as default parameter..\n"   
        "4. \"mode\"          (string, optional) The mode is ecb,and ecb is setted as default parameter. \n"
        "\nResult:\n"
        "{                      (json object)\n"   
      //  "  \"result\"         (string, The sm4 successfully decrypt. )\n"
        "  \"transcode\"      (string, This is the decode . )\n"
        "  \"mode\"           (string, This is the mode of decrypt. )\n"
        "  \"plaintextLen\"   (string, This is the length of plaintext. )\n"
        "  \"plaintext\"      (string, The plaintext decrypted from ciphertext by key.\n"
        "}\n"
        "\nExamples:\n"
        + HelpExampleCli("sm4recoverplaintext", "\"ciphertext\",\"key\",\"transcode\",\"mode\" ")
        + HelpExampleRpc("sm4recoverplaintext", "\"ciphertext\",\"key\",\"transcode\",\"mode\" ")
         );
    }
    

     StruCrypto *struCrypto = new StruCrypto;
     ClassSM4 classSM4;
     UniValue valRequest;
     UniValue result(UniValue::VOBJ);
     int ret = -1;
     JudgeInputParameters *judgeInputPara = new JudgeInputParameters;
    
    struCrypto->strCiphertext  = request.params[0].get_str();
    struCrypto->strKey = request.params[1].get_str();
    struCrypto->strTranscode = "hex";
    struCrypto->strMode = "ecb";
    if(3 == request.params.size())
    {
        string strParamTemp = request.params[2].get_str();
        if(0 == strParamTemp.compare("ecb") || 0 == strParamTemp.compare("ECB") || 0 == strParamTemp.compare("cbc") 
            || 0 == strParamTemp.compare("CBC") )
        {
            struCrypto->strMode = request.params[2].get_str();
        }
        else
        {
            struCrypto->strTranscode = request.params[2].get_str();
        }
    }
    else if(4 == request.params.size())
    {
        struCrypto->strTranscode = request.params[2].get_str();
        struCrypto->strMode = request.params[3].get_str();
    }
    
    /*judge input parameters*/
    judgeInputPara->JudgeSM4Dec(struCrypto);

    struCrypto->strAlgorithm = "sm4";
    if (0 == struCrypto->strAlgorithm.compare("SM4") || 0 == struCrypto->strAlgorithm.compare("sm4") )
    {
        StruContext *struContext = new StruContext;
        memset(struContext, 0, sizeof(struContext));
        struContext->cMode = struCrypto->strMode.c_str();

        struContext->cKey = new unsigned char[SM4_KEY_LEN];
        memset(struContext->cKey, 0, SM4_KEY_LEN);
        struContext->iKeyLen = 0; 

        if( 0 == struCrypto->strTranscode.compare("HEX") || 0 == struCrypto->strTranscode.compare("hex"))
        {
            HexTranscode *hexTranscode = new HexTranscode(); 
            struContext->iKeyLen =  hexTranscode->HexDecode(&struCrypto->strKey, struCrypto->strKey.length(), struContext->cKey);
            if(struContext->iKeyLen <= 0 )
            {
                cout <<"The hex doesn't decode  at sm4recoverplaintext. "<<endl;
                LogPrintf("The hex doesn't decode  at sm4recoverplaintext.\n");
                throw JSONRPCError(HEX_DECODE_ERROR, "The hex doesn't decode  at sm4recoverplaintext."); 
                //return -1;
            }
        
            cout<<" hex encode : struContext->iKeyLen =" << struContext->iKeyLen<<", struContext->cKey= "<<struContext->cKey<<endl;
            LogPrintf("hex encode :struContext->iKeyLen = %d,   struContext->cKey=%s.\n",struContext->iKeyLen,  struContext->cKey);
            delete hexTranscode;
        }
        else
        {
            memcpy(struContext->cKey,(char *) struCrypto->strKey.c_str(), struCrypto->strKey.length());
		    struContext->iKeyLen = struCrypto->strKey.length();
        }
        

        cout<<"struContext->iKeyLen="<<struContext->iKeyLen<<", struContext->cKey= "<<struContext->cKey<<endl;
     	
        struContext->cCiphertextIn = new unsigned char[MSG_LEN_TRANSCODE];
        memset(struContext->cCiphertextIn, 0, MSG_LEN_TRANSCODE);
        struContext->iCiphertextLenIn = 0;
        //解码
        if( 0 == struCrypto->strTranscode.compare("BASE64") || 0 == struCrypto->strTranscode.compare("base64"))
        {
            Base64 *base64 = new Base64(); 
            struContext->iCiphertextLenIn = base64->Base64Decode(&struCrypto->strCiphertext, struCrypto->strCiphertext.length() , struContext->cCiphertextIn);
            if(struContext->iCiphertextLenIn <= 0 )
            {
                cout <<"The base64 doesn't decode  at sm4recoverplaintext. "<<endl;
                LogPrintf("The base64 doesn't decode   at sm4recoverplaintext .\n");
                throw JSONRPCError(BASE64_DECODE_ERROR, "The base64 doesn't decode  at sm4recoverplaintext.");  
                //return -1;
            }
            
       
            cout<<"base64 decode : struContext->iCiphertextLenIn= "<< struContext->iCiphertextLenIn<<", struContext->cCiphertextIn="<< struContext->cCiphertextIn<<endl;
            LogPrintf("base64 decode :struContext->iCiphertextLenIn = %d,   struContext->cCiphertextIn=%u.\n",
                 struContext->iCiphertextLenIn,  struContext->cCiphertextIn);
            
            delete base64;
        }
        else if( 0 == struCrypto->strTranscode.compare("BASE58") || 0 == struCrypto->strTranscode.compare("base58"))
        {
            Base58 *base58 = new Base58(); 
            struContext->iCiphertextLenIn = base58->Base58Decode(&struCrypto->strCiphertext, struCrypto->strCiphertext.length(), struContext->cCiphertextIn);
            if(struContext->iCiphertextLenIn <= 0 )
            {
                cout <<"The base58 doesn't decode  at sm4recoverplaintext."<<endl;
                LogPrintf("The base58 doesn't decode  at sm4recoverplaintext.\n");
                throw JSONRPCError(BASE58_DECODE_ERROR, "The base58 doesn't decode  at sm4recoverplaintext.");  
                //return -1;
            }  
           
            
            cout<<"base58 decode : struContext->iCiphertextLenIn= "<< struContext->iCiphertextLenIn<<", struContext->cCiphertextIn="<< struContext->cCiphertextIn<<endl;       
            LogPrintf("base58 encode :struContext->iCiphertextLenIn = %d,   struContext->cCiphertextIn=%u.\n",
                 struContext->iCiphertextLenIn,  struContext->cCiphertextIn);
            delete base58;
        }
        else if( 0 == struCrypto->strTranscode.compare("HEX") || 0 == struCrypto->strTranscode.compare("hex"))
        {
            HexTranscode *hexTranscode = new HexTranscode(); 
            struContext->iCiphertextLenIn =  hexTranscode->HexDecode(&struCrypto->strCiphertext, struCrypto->strCiphertext.length(), struContext->cCiphertextIn);
            if(struContext->iCiphertextLenIn <= 0 )
            {
                cout <<"The hex doesn't decode  at sm4recoverplaintext. "<<endl;
                LogPrintf("The hex doesn't decode  at sm4recoverplaintext.\n");
                throw JSONRPCError(HEX_DECODE_ERROR, "The hex doesn't decode  at sm4recoverplaintext."); 
                //return -1;
            }
            #if 0
            cout<<" hex encode : struContext->iCiphertextLenIn =" << struContext->iCiphertextLenIn<<", struContext->cCiphertextIn= "<<struContext->cCiphertextIn<<endl;
            LogPrintf("hex encode :struContext->iCiphertextLenIn = %d,   struContext->cCiphertextIn=%u.\n",
                 struContext->iCiphertextLenIn,  struContext->cCiphertextIn);
            FILE *fpOut;
            fpOut = fopen("sm4cipherhexdec.txt","w");
            if(NULL == fpOut)
            {
                cout <<"Cann't open sm4cipherhexdec.txt by write. "<<endl;
                LogPrintf("Cann't open sm4cipherhexdec.txt by write.\n");
                throw JSONRPCError(HEX_DECODE_ERROR, "Cann't open sm4cipherhexdec.txt by write."); 
            }
            fwrite(struContext->cCiphertextIn, 1, struContext->iCiphertextLenIn, fpOut);
            fclose(fpOut);
             #endif
            delete hexTranscode;
        }
        else
        {
            cout <<" The transcode is not decode to base64 、 base58 or hex at sm4recoverplaintext."<<endl;
            LogPrintf("The transcode is not decode to base64 、 base58 or hex at sm4recoverplaintext.\n");
            throw JSONRPCError(TRANSCODE_ERROR, "The transcode is not decode to base64 、 base58 or hex at sm4recoverplaintext."); 
            //return -1;
        }
    	
        struContext->cPlaintextOut = new unsigned char[MSG_LEN_OUT];
        memset(struContext->cPlaintextOut, 0, MSG_LEN_OUT);
        struContext->iPlaintextLenOut = 0;
        ret = classSM4.SM4_Dec(struContext);
        if(ret != 0)
        {
            cout <<" The SM4_Dec doesn't successfully decrypt." <<endl;
            LogPrintf("The SM4_Dec doesn't successfully decrypt.\n");
            throw JSONRPCError(SM4_DEC_ERROR, "The SM4_Dec doesn't successfully decrypt.");
            //return -1;
        }     
        
        char * cPlaintextOutTemp = new char[MSG_LEN_OUT];
        memset(cPlaintextOutTemp, 0, MSG_LEN_OUT);
        int iPlaintextLenOut = 0;
        iPlaintextLenOut = struContext->iPlaintextLenOut;
        for(int i = 0; i < iPlaintextLenOut; i++ )
        {
            cPlaintextOutTemp[i] = struContext->cPlaintextOut[i];
            cout<<struContext->cPlaintextOut[i]<<" ";
        }
        cout<<endl;
       
       // result.push_back(Pair("result", "the sm4 successfully decrypt."));
        result.push_back(Pair("transcode", struCrypto->strTranscode));
        result.push_back(Pair("mode", struCrypto->strMode));
        result.push_back(Pair("plaintextLen", iPlaintextLenOut));
        result.push_back(Pair("plaintext", cPlaintextOutTemp));

        //fclose(fpIn);
       
       
        delete[] cPlaintextOutTemp;
        delete[]  struContext->cKey;
        delete[]  struContext->cCiphertextIn;
        delete[]  struContext->cPlaintextOut;
        delete struContext;
        delete struCrypto;
        delete judgeInputPara;
    } 
    else
    {
        cout << "The algorithm is not SM4 at sm4recoverplaintext." <<endl;
        LogPrintf("The algorithm is not SM4 at sm4recoverplaintext.\n");
        throw JSONRPCError(SM4_ERROR, "The algorithm is not SM4 at sm4recoverplaintext.");  
    }
    
    return result;
}



static const CRPCCommand commands[] =
{ //  category              name                            actor (function)         okSafe argNames
  //  --------------------- ------------------------         -----------------------  ------ ----------
    { "maingmcrypto",         "getinfo",                     &getinfo,                    true,  {} }, //0
    { "maingmcrypto",         "sm2generatekeypairs",         &sm2generatekeypairs,        true,  { "transcode"} }, 
    { "maingmcrypto",         "sm2getciphertext",            &sm2getciphertext,           true,  {"plaintext", "transcode"} }, 
    { "maingmcrypto",         "sm2recoverplaintext",         &sm2recoverplaintext,        true,  {"ciphertext", "transcode"} }, 
    { "maingmcrypto",         "sm2getsignatureinfo",         &sm2getsignatureinfo,        true,  {"plaintext", "transcode"} }, 
    { "maingmcrypto",         "sm2getsignatureverify",       &sm2getsignatureverify,      true,  {"plaintext", "signature", "transcode"} }, 
    { "maingmcrypto",         "sm3getdigest",                &sm3getdigest,               true,  {"plaintext", "transcode"} },
    { "maingmcrypto",         "sm4getciphertext",            &sm4getciphertext,           true,  {"plaintext","key", "transcode","mode"} }, 
    { "maingmcrypto",         "sm4recoverplaintext",         &sm4recoverplaintext,        true,  {"ciphertext","key", "transcode","mode" } }, 

};

void RegisterMainGMCRYPTOCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}