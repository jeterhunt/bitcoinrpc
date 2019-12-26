#include <stdio.h>
#include "rpc/server.h"
#include "rpc/register.h"
#include "util.h"
#include "init.h"
#include "httpserver.h"
#include "httprpc.h"
#include "utilstrencodings.h"

#include <boost/thread.hpp>

//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Exit and Abort
//
//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// Argument values for exit()
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

bool AppInit(int argc, char* argv[])
{

    boost::thread_group threadGroup;
    ParseParameters(argc, argv);

    if (fPrintToDebugLog)
        OpenDebugLog();

    try
    {
        ReadConfigFile(GetArg("-conf", "/home/wen/gmcrypto/gmcrypto/gmcrypto.conf"));
    } catch (const std::exception& e) {
        printf("Error reading configuration file: %s\n", e.what());
        return false;
    }


    RegisterAllCoreRPCCommands(tableRPC);
    if (!AppInitServers(threadGroup))
            return false;

    SetRPCWarmupFinished();
    WaitForShutdown(&threadGroup);
    Shutdown();

    return true;
}

int main(int argc, char* argv[])
{
    printf("THIS IS GM CRYPTO RPC SERVER!!!\n");

    int ret = (AppInit(argc, argv) ? EXIT_SUCCESS : EXIT_FAILURE);
    printf("ret:%d", ret);

    return ret;
}