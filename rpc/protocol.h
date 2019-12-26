#ifndef WEALEDGERSSL_RPCPROTOCOL_H
#define WEALEDGERSSL_RPCPROTOCOL_H

#include <list>
#include <map>
#include <stdint.h>
#include <string>
#include <boost/filesystem.hpp>

#include <univalue.h>

//! HTTP status codes
enum HTTPStatusCode
{
    HTTP_OK                    = 200,
    HTTP_BAD_REQUEST           = 400,
    HTTP_UNAUTHORIZED          = 401,
    HTTP_FORBIDDEN             = 403,
    HTTP_NOT_FOUND             = 404,
    HTTP_BAD_METHOD            = 405,
    HTTP_INTERNAL_SERVER_ERROR = 500,
    HTTP_SERVICE_UNAVAILABLE   = 503,
};

//! Bitcoin RPC error codes
enum RPCErrorCode
{
    //! Standard JSON-RPC 2.0 errors
    RPC_INVALID_REQUEST  = -32600,
    RPC_METHOD_NOT_FOUND = -32601,
    RPC_INVALID_PARAMS   = -32602,
    RPC_INTERNAL_ERROR   = -32603,
    RPC_PARSE_ERROR      = -32700,

    //! General application defined errors
    RPC_MISC_ERROR                  = -1,  //!< std::exception thrown in command handling
    RPC_FORBIDDEN_BY_SAFE_MODE      = -2,  //!< Server is in safe mode, and command is not allowed in safe mode
    RPC_TYPE_ERROR                  = -3,  //!< Unexpected type was passed as parameter
    RPC_INVALID_ADDRESS_OR_KEY      = -5,  //!< Invalid address or key
    RPC_OUT_OF_MEMORY               = -7,  //!< Ran out of memory during operation
    RPC_INVALID_PARAMETER           = -8,  //!< Invalid, missing or duplicate parameter
    RPC_DATABASE_ERROR              = -20, //!< Database error
    RPC_DESERIALIZATION_ERROR       = -22, //!< Error parsing or validating structure in raw format
    RPC_VERIFY_ERROR                = -25, //!< General error during transaction or block submission
    RPC_VERIFY_REJECTED             = -26, //!< Transaction or block was rejected by network rules
    RPC_VERIFY_ALREADY_IN_CHAIN     = -27, //!< Transaction already in chain
    RPC_IN_WARMUP                   = -28, //!< Client still warming up

    //! Aliases for backward compatibility
    RPC_TRANSACTION_ERROR           = RPC_VERIFY_ERROR,
    RPC_TRANSACTION_REJECTED        = RPC_VERIFY_REJECTED,
    RPC_TRANSACTION_ALREADY_IN_CHAIN= RPC_VERIFY_ALREADY_IN_CHAIN,

    //! P2P client errors
    RPC_CLIENT_NOT_CONNECTED        = -9,  //!< Bitcoin is not connected
    RPC_CLIENT_IN_INITIAL_DOWNLOAD  = -10, //!< Still downloading initial blocks
    RPC_CLIENT_NODE_ALREADY_ADDED   = -23, //!< Node is already added
    RPC_CLIENT_NODE_NOT_ADDED       = -24, //!< Node has not been added before
    RPC_CLIENT_NODE_NOT_CONNECTED   = -29, //!< Node to disconnect not found in connected nodes
    RPC_CLIENT_INVALID_IP_OR_SUBNET = -30, //!< Invalid IP/Subnet
    RPC_CLIENT_P2P_DISABLED         = -31, //!< No valid connection manager instance found

    //! Wallet errors
    RPC_WALLET_ERROR                = -4,  //!< Unspecified problem with wallet (key not found etc.)
    RPC_WALLET_INSUFFICIENT_FUNDS   = -6,  //!< Not enough funds in wallet or account
    RPC_WALLET_INVALID_ACCOUNT_NAME = -11, //!< Invalid account name
    RPC_WALLET_KEYPOOL_RAN_OUT      = -12, //!< Keypool ran out, call keypoolrefill first
    RPC_WALLET_UNLOCK_NEEDED        = -13, //!< Enter the wallet passphrase with walletpassphrase first
    RPC_WALLET_PASSPHRASE_INCORRECT = -14, //!< The wallet passphrase entered was incorrect
    RPC_WALLET_WRONG_ENC_STATE      = -15, //!< Command given in wrong wallet encryption state (encrypting an encrypted wallet etc.)
    RPC_WALLET_ENCRYPTION_FAILED    = -16, //!< Failed to encrypt the wallet
    RPC_WALLET_ALREADY_UNLOCKED     = -17, //!< Wallet is already unlocked

    RPC_IPFS_ERROR                  = -32, //

    //! Contract errors
    RPC_CONTRACT_ERROR              = -100, //!< Unspecified problem with contract
    RPC_CONTRACT_EXISTED            = -101, //!< The Contract is existed.

    RPC_CA_NOTFOUND                 = -102, //!< The certificate can not be found.

    
    //! sm2
     SM2_KEY_ERROR                  = -201,  //!< SM2_Key doesn't successfully product sm2privateKey.pem and sm2publicKeu.pem!
     SM2_PUBLIC_KEY_READ_ERROR      = -202,  //!< Cannot open sm2publicKey.pem by read.
     SM2_ENC_ERROR                  = -203,  //!< SM2_Enc doesn't successfully encrypt.
     BASE64_ENCODE_ERROR            = -204,  //!< The base64 doesn't encode. 
     BASE58_ENCODE_ERROR            = -205,  //!< The base58 doesn't encode.
     HEX_ENCODE_ERROR               = -206,  //!< The hex is doesn't encode.
     BASE64_DECODE_ERROR            = -207,  //!< The base64 doesn't decode.
     BASE58_DECODE_ERROR            = -208,  //!< The base58 doesn't decode  .
     HEX_DECODE_ERROR               = -209,  //!< The hex doesn't decode.
     SM2_DEC_ERROR                  = -210,  //!< SM2_Dec  doesn't successfully decrypt.
     SM2_ERROR                      = -211,  //!< The algorithm is not SM2.
     SM2_SIG_ERROR                  = -212,  //!< SM2_Sig  doesn't successfully signature.
     SM2_VER_ERROR                  = -213,  //!< SM2_Ver doesn't  successfully verify.
     TRANSCODE_ERROR                = -214,  //!< The transcodes is not base64 、base58、hex.
     PLAINTEXT_ERROR                = -215,  //!< The length of plaintext  is less than or equal to 0, or is bigger to 10*1024 bytes(10KB).
     CIPHERTEXT_ERROR               = -216,  //!< The ciphertext of tanscode is less than or equal to 0, or  bigger to 50*1024 bytes(50KB)
     SIGNATURE_INFORMATION_ERROR    = -217,  //!< The ciphertext of tanscode is less than or equal to 0, or  bigger to 50*1024 bytes(50KB).

    //!sm3
    SM3_DIG_ERROR                  = -221,  //!< SM3_Digest doesn't successfully digest.
    SM3_ERROR                      = -222,  //!< The algorithm is not SM3.
    //!sm4
    SM4_ENC_ERROR                  = -231,  //!< The SM4_Enc doesn't successfully encrypt.
    SM4_DEC_ERROR                  = -232,  //!< The SM4_Dec doesn't successfully decrypt.
    SM4_KEY_ERROR                  = -233,  //!< The key is less than or equal to 0 , or bigger to 16 bytes .
    SM4_ERROR                      = -234,  //!< The algorithm is not SM4.
    SM4_MODE_ERROR                 = -235,  //!< This is not ecb or cbc.
    SM4_KEY_HEX_ERROR              = -236,  //!< The key is less than or equal to 0 , or bigger to 32 , or it's length divided by 2 is not equal to 0.
};

UniValue JSONRPCRequestObj(const std::string& strMethod, const UniValue& params, const UniValue& id);
UniValue JSONRPCReplyObj(const UniValue& result, const UniValue& error, const UniValue& id);
std::string JSONRPCReply(const UniValue& result, const UniValue& error, const UniValue& id);
UniValue JSONRPCError(int code, const std::string& message);

/** Get name of RPC authentication cookie file */
boost::filesystem::path GetAuthCookieFile();
/** Generate a new RPC authentication cookie and write it to disk */
bool GenerateAuthCookie(std::string *cookie_out);
/** Read the RPC authentication cookie from disk */
bool GetAuthCookie(std::string *cookie_out);
/** Delete RPC authentication cookie from disk */
void DeleteAuthCookie();

#endif //WEALEDGERSSL_RPCPROTOCOL_H