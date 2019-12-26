
#include "httprpc.h"
#include "rpc/protocol.h"
#include "rpc/server.h"
#include "httpserver.h"
#include "util.h"
#include "netaddress.h"
#include "utilstrencodings.h"
#include <stdio.h>

#include <boost/algorithm/string.hpp> // boost::trim
#include <boost/foreach.hpp> //BOOST_FOREACH

/** WWW-Authenticate to present with 401 Unauthorized response */
static const char* WWW_AUTH_HEADER_DATA = "Basic realm=\"jsonrpc\"";

/** Simple one-shot callback timer to be used by the RPC mechanism to e.g.
 * re-lock the wallet.
 */
class HTTPRPCTimer : public RPCTimerBase
{
public:
    HTTPRPCTimer(struct event_base* eventBase, boost::function<void(void)>& func, int64_t millis) :
        ev(eventBase, false, func)
    {
        struct timeval tv;
        tv.tv_sec = millis/1000;
        tv.tv_usec = (millis%1000)*1000;
        ev.trigger(&tv);
    }
private:
    HTTPEvent ev;
};

class HTTPRPCTimerInterface : public RPCTimerInterface
{
public:
    HTTPRPCTimerInterface(struct event_base* _base) : base(_base)
    {
    }
    const char* Name()
    {
        return "HTTP";
    }
    RPCTimerBase* NewTimer(boost::function<void(void)>& func, int64_t millis)
    {
        return new HTTPRPCTimer(base, func, millis);
    }
private:
    struct event_base* base;
};

/* Pre-base64-encoded authentication token */
static std::string strRPCUserColonPass;
/* Stored RPC timer interface (for unregistration) */
static HTTPRPCTimerInterface* httpRPCTimerInterface = 0;

static void JSONErrorReply(HTTPRequest* req, const UniValue& objError, const UniValue& id)
{
    // Send error reply from json-rpc error object
    int nStatus = HTTP_INTERNAL_SERVER_ERROR;
    int code = find_value(objError, "code").get_int();

    if (code == RPC_INVALID_REQUEST)
        nStatus = HTTP_BAD_REQUEST;
    else if (code == RPC_METHOD_NOT_FOUND)
        nStatus = HTTP_NOT_FOUND;

    std::string strReply = JSONRPCReply(NullUniValue, objError, id);

    req->WriteHeader("Content-Type", "application/json");
    req->WriteReply(nStatus, strReply);
}

//This function checks username and password against -rpcauth
//entries from config file.
static bool multiUserAuthorized(std::string strUserPass)
{    
    // if (strUserPass.find(":") == std::string::npos) {
    //     return false;
    // }
    // std::string strUser = strUserPass.substr(0, strUserPass.find(":"));
    // std::string strPass = strUserPass.substr(strUserPass.find(":") + 1);

    // if (mapMultiArgs.count("-rpcauth") > 0) {
    //     //Search for multi-user login/pass "rpcauth" from config
    //     BOOST_FOREACH(std::string strRPCAuth, mapMultiArgs.at("-rpcauth"))
    //     {
    //         std::vector<std::string> vFields;
    //         boost::split(vFields, strRPCAuth, boost::is_any_of(":$"));
    //         if (vFields.size() != 3) {
    //             //Incorrect formatting in config file
    //             continue;
    //         }

    //         std::string strName = vFields[0];
    //         if (!TimingResistantEqual(strName, strUser)) {
    //             continue;
    //         }

    //         std::string strSalt = vFields[1];
    //         std::string strHash = vFields[2];

    //         static const unsigned int KEY_SIZE = 32;
    //         unsigned char out[KEY_SIZE];

    //         CHMAC_SHA256(reinterpret_cast<const unsigned char*>(strSalt.c_str()), strSalt.size()).Write(reinterpret_cast<const unsigned char*>(strPass.c_str()), strPass.size()).Finalize(out);
    //         std::vector<unsigned char> hexvec(out, out+KEY_SIZE);
    //         std::string strHashFromPass = HexStr(hexvec);

    //         if (TimingResistantEqual(strHashFromPass, strHash)) {
    //             return true;
    //         }
    //     }
    // }
    // return false;

    return true;
}

static bool RPCAuthorized(const std::string& strAuth, std::string& strAuthUsernameOut)
{
    if (strRPCUserColonPass.empty()) // Belt-and-suspenders measure if InitRPCAuthentication was not called
        return false;
    if (strAuth.substr(0, 6) != "Basic ")
        return false;
    std::string strUserPass64 = strAuth.substr(6);
    boost::trim(strUserPass64);
    std::string strUserPass = DecodeBase64(strUserPass64);

    if (strUserPass.find(":") != std::string::npos)
        strAuthUsernameOut = strUserPass.substr(0, strUserPass.find(":"));

    //Check if authorized under single-user field
    if (TimingResistantEqual(strUserPass, strRPCUserColonPass)) {
        return true;
    }
    return multiUserAuthorized(strUserPass);
}

#ifdef WIN32
// #include "stdafx.h"
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <string.h>
#include <ws2tcpip.h>
#pragma comment(lib,"ws2_32.lib") 

#else
#include <unistd.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#endif
static std::vector<std::string> GetLocalIPs()
{
    std::vector<std::string> ips;
#ifdef WIN32
    struct hostent *thishost;
    struct addrinfo *ailist, *aip;
    struct addrinfo addrInfoV6;
    struct sockaddr_in6 *sinp6;
    char myName[80];
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;
    wVersionRequested = MAKEWORD(2, 0);
    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0)
    {
        return ips;
    }
    gethostname(myName, 80);
    thishost = gethostbyname(myName);
    if (thishost == NULL || thishost->h_addr_list == NULL || thishost->h_addr_list[0] == NULL)
    {
        LogPrintf("Error: gethostbyname from %s failed\n", myName);
        return ips;
    }
    printf("hostname is %s\n", myName);
    char **pptr = NULL;
    try
    {
        // get ipv4 addresses
        for (pptr = thishost->h_aliases; pptr != NULL && *pptr != NULL; pptr++)
        {
            LogPrintf("aliases: %s\n", *pptr);
        }
        switch (thishost->h_addrtype)
        {
        case AF_INET:
        case AF_INET6:
        {
            pptr = thishost->h_addr_list;
            for (; pptr != NULL && *pptr != NULL; pptr++)
            {
             std::string address = inet_ntoa(*(in_addr*)*pptr);
             ips.push_back(address);
            }
        }
            break;
        default:
            break;
        }
        // get ipv6 addresses
        addrInfoV6.ai_family = AF_INET6;
        addrInfoV6.ai_socktype = SOCK_STREAM;
        addrInfoV6.ai_flags = AI_PASSIVE;
        addrInfoV6.ai_protocol = 0;
        addrInfoV6.ai_addrlen = 0;   
        addrInfoV6.ai_canonname = NULL;
        addrInfoV6.ai_addr = NULL;
        addrInfoV6.ai_next = NULL;
        err = getaddrinfo(myName, "9333", &addrInfoV6, &ailist);
        if (err < 0)
        {
            LogPrintf("Error: getaddrinfo error\n");
            return ips;
        }
        for (aip = ailist; aip != NULL; aip = aip->ai_next) 
        {
            aip->ai_family = AF_INET6;
            sinp6 = (struct sockaddr_in6 *)aip->ai_addr;
            int i;
            const int len = 128;
            char buff[len];
            int pos = 0;
            for (i = 0; i < 16; i++)
            {
                if (((i - 1) % 2) && (i > 0))
                {
                    pos += sprintf_s(buff + pos, len - pos, ":");
                }
                pos += sprintf_s(buff + pos, len - pos, "%02x", sinp6->sin6_addr.u.Byte[i]);
            }
            std::string strIp(buff, buff + pos);
            ips.push_back(strIp);
        }
    }
    catch (...)
    {
        LogPrintf("Fatal error: get local address error\n");
    }

    WSACleanup();
#else
    try
    {
        // get ipv4 addresses
        int sfd, intr;
        struct ifreq buf[16];
        struct ifconf ifc;
        sfd = socket(AF_INET, SOCK_DGRAM, 0); 
        if (sfd < 0)
            return ips;
        ifc.ifc_len = sizeof(buf);
        ifc.ifc_buf = (caddr_t)buf;
        if (ioctl(sfd, SIOCGIFCONF, (char *)&ifc))
            return ips;
        intr = ifc.ifc_len / sizeof(struct ifreq);
        while (intr-- > 0)
        {
            if (!(ioctl(sfd, SIOCGIFADDR, (char *)&buf[intr])))
            {
                std::string ip = inet_ntoa(((struct sockaddr_in*)(&buf[intr].ifr_addr))->sin_addr);
                std::cout << "ipv4 address: " << ip << std::endl;
                ips.push_back(ip);
            }
        }
        close(sfd);

        //get ipv6 addresses
        char hostname[256];
        gethostname(hostname, sizeof(hostname));
        struct hostent* host = gethostbyname(hostname);
        if (host == NULL || host->h_addr_list == NULL || *host->h_addr_list == NULL)
        {
            LogPrintf("Fatal error: get ipv6 error\n");
            return ips;
        }

        if (host->h_addrtype != AF_INET6)
            return ips;
        char pstr[INET6_ADDRSTRLEN];
        char** pptr = host->h_addr_list;
        for (; pptr != NULL && *pptr != NULL; pptr++)
        {
            memset(pstr, 0, INET6_ADDRSTRLEN);
            const char* ret = inet_ntop(host->h_addrtype, *pptr, pstr, sizeof(pstr));
            if (ret == NULL)
                return ips;
            std::string ip(pstr, pstr + INET6_ADDRSTRLEN);
            std::cout << "ipv6 address: " << ip << std::endl;
            ips.push_back(ip);
        }
    }
    catch(...)
    {
        LogPrintf("Fatal error: get local address unexpected error\n");
    }
#endif
    return ips;
}

std::vector<std::string> GetAllowedIPs()
{
    if (mapMultiArgs.count("-rpcadminip"))
    {
        return mapMultiArgs.at("-rpcadminip");
    }
}

bool IsAdministrator(HTTPRequest* req) 
{
    std::string strIP = req->GetPeer().ToStringIP();
    LogPrintf("Remote IP Address: %s\n", strIP.c_str());
    
    static std::vector<std::string> vecLocalIPs = GetLocalIPs();
    static std::vector<std::string> vecAllowIPs = GetAllowedIPs();

    for (int i = 0; i < vecLocalIPs.size(); i++)
    {
        LogPrintf("Local IP: %s\n", vecLocalIPs[i].c_str());
        if (strIP == vecLocalIPs[i])
        {
            return true;
        }
        
    }
    for (int i = 0; i < vecAllowIPs.size(); i++)
    {
        LogPrintf("Allowed IP: %s\n", vecAllowIPs[i].c_str());
        if (strIP == vecAllowIPs[i])
        {
            return true;
        }
    }
    
    return false;
}

bool RPCServiceCheck(bool fAdministrator, std::string strMethod)
{
    // std::cout << "method: " << strprintf("-%s-service", strMethod) << endl;
    // std::cout << "service: " << GetBoolArg(strprintf("-%s-service", strMethod), true) << endl;
    
    if (!fAdministrator && !GetBoolArg(strprintf("-%s-service", strMethod), true)) {
        return false;
    }

    return true;
}

static bool HTTPReq_JSONRPC(HTTPRequest* req, const std::string &)
{
    bool fAdministrator = IsAdministrator(req);

    // JSONRPC handles only POST
    if (req->GetRequestMethod() != HTTPRequest::POST) {
        req->WriteReply(HTTP_BAD_METHOD, "JSONRPC server handles only POST requests");
        return false;
    }
    // Check authorization
    std::pair<bool, std::string> authHeader = req->GetHeader("authorization");
    if (!authHeader.first) {
        req->WriteHeader("WWW-Authenticate", WWW_AUTH_HEADER_DATA);
        req->WriteReply(HTTP_UNAUTHORIZED);
        return false;
    }

    JSONRPCRequest jreq;
    if (!RPCAuthorized(authHeader.second, jreq.authUser)) {
        LogPrintf("ThreadRPCServer incorrect password attempt from %s\n", req->GetPeer().ToString());

        /* Deter brute-forcing
           If this results in a DoS the user really
           shouldn't have their RPC port exposed. */
        MilliSleep(250);

        req->WriteHeader("WWW-Authenticate", WWW_AUTH_HEADER_DATA);
        req->WriteReply(HTTP_UNAUTHORIZED);
        return false;
    }

    try {
        // Parse request
        UniValue valRequest;
        if (!valRequest.read(req->ReadBody()))
            throw JSONRPCError(RPC_PARSE_ERROR, "Parse error");

        // Set the URI
        jreq.URI = req->GetURI();

        std::string strReply;
        // singleton request
        if (valRequest.isObject()) 
        {
            jreq.parse(valRequest);
            if (!RPCServiceCheck(fAdministrator, jreq.strMethod)) {
                req->WriteReply(HTTP_UNAUTHORIZED, "The rpccommond authorization failed");
                return false;
            }

            UniValue result = tableRPC.execute(jreq);
            // Send reply
            strReply = JSONRPCReply(result, NullUniValue, jreq.id);
        }  
        // array of requests
        else if (valRequest.isArray()) 
        {
            // strReply = JSONRPCExecBatch(valRequest.get_array());
            
            UniValue vReq = valRequest.get_array();
            UniValue ret(UniValue::VARR);
            for (unsigned int reqIdx = 0; reqIdx < vReq.size(); reqIdx++) 
            {
                JSONRPCRequest jreq;
                jreq.parse(vReq[reqIdx]);

                if (!RPCServiceCheck(fAdministrator, jreq.strMethod)) {
                    req->WriteReply(HTTP_UNAUTHORIZED, "The rpccommond authorization failed");
                    return false;
                }
                ret.push_back(JSONRPCExecOne(jreq));
            }
            strReply = ret.write() + "\n";
        }
        else {
            throw JSONRPCError(RPC_PARSE_ERROR, "Top-level object parse error");
        }
        
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_OK, strReply);
    } catch (const UniValue& objError) {
        JSONErrorReply(req, objError, jreq.id);
        return false;
    } catch (const std::exception& e) {
        JSONErrorReply(req, JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
        return false;
    }
    return true;
}

static bool InitRPCAuthentication()
{
    if (GetArg("-rpcpassword", "") == "")
    {
        printf("No rpcpassword set - using random cookie authentication\n");
        // if (!GenerateAuthCookie(&strRPCUserColonPass)) {
        //     uiInterface.ThreadSafeMessageBox(
        //         _("Error: A fatal internal error occurred, see debug.log for details"), // Same message as AbortNode
        //         "", CClientUIInterface::MSG_ERROR);
        //     return false;
        // }
    } else {
        LogPrintf("Config options rpcuser and rpcpassword will soon be deprecated. Locally-run instances may remove rpcuser to use cookie-based auth, or may be replaced with rpcauth. Please see share/rpcuser for rpcauth auth generation.\n");
        strRPCUserColonPass = GetArg("-rpcuser", "") + ":" + GetArg("-rpcpassword", "");
    }
    return true;
}

bool StartHTTPRPC()
{
    LogPrint("rpc", "Starting HTTP RPC server\n");
    if (!InitRPCAuthentication())
        return false;

    RegisterHTTPHandler("/", true, HTTPReq_JSONRPC);

    assert(EventBase());
    httpRPCTimerInterface = new HTTPRPCTimerInterface(EventBase());
    RPCSetTimerInterface(httpRPCTimerInterface);
    return true;
}

void InterruptHTTPRPC()
{
    LogPrint("rpc", "Interrupting HTTP RPC server\n");
}

void StopHTTPRPC()
{
    LogPrint("rpc", "Stopping HTTP RPC server\n");
    UnregisterHTTPHandler("/", true);
    if (httpRPCTimerInterface) {
        RPCUnsetTimerInterface(httpRPCTimerInterface);
        delete httpRPCTimerInterface;
        httpRPCTimerInterface = 0;
    }
}