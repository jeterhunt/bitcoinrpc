#include "rpc/server.h"
#include "rpc/register.h"
#include "httpserver.h"
#include "httprpc.h"
#include "netbase.h"
#include "util.h"
#include "sync.h"
#include <stdint.h>
#include <stdio.h>
#include <memory>
#include <fstream>

#include <boost/thread.hpp>

void Shutdown()
{
    LogPrintf("%s: In progress...\n", __func__);
    static CCriticalSection cs_Shutdown;
    TRY_LOCK(cs_Shutdown, lockShutdown);
    if (!lockShutdown)
        return;
    
    RenameThread("GMCRYPTO-shutoff");
    StopHTTPRPC();
    //StopREST();
    StopRPC();
    StopHTTPServer();

    LogPrintf("%s: done\n", __func__);
}

void Interrupt(boost::thread_group& threadGroup)
{
    InterruptHTTPServer();
    InterruptHTTPRPC();
    InterruptRPC();
    //InterruptREST();
    threadGroup.interrupt_all();
}

void OnRPCStarted()
{
    //uiInterface.NotifyBlockTip.connect(&RPCNotifyBlockChange);
}

void OnRPCStopped()
{
    //uiInterface.NotifyBlockTip.disconnect(&RPCNotifyBlockChange);
    //RPCNotifyBlockChange(false, nullptr);
    //cvBlockChange.notify_all();
    printf("GMCRYPTO stopped.\n");
}

void OnRPCPreCommand(const CRPCCommand& cmd)
{
    // Observe safe mode
    // std::string strWarning = GetWarnings("rpc");
    // if (strWarning != "" && !GetBoolArg("-disablesafemode", DEFAULT_DISABLE_SAFEMODE) &&
    //    !cmd.okSafeMode)
    //    throw JSONRPCError(RPC_FORBIDDEN_BY_SAFE_MODE, std::string("Safe mode: ") + strWarning);
}

std::atomic<bool> fRequestShutdown(false);
std::atomic<bool> fDumpMempoolLater(false);

void StartShutdown()
{
    fRequestShutdown = true;
}
bool ShutdownRequested()
{
    return fRequestShutdown;
}

void WaitForShutdown(boost::thread_group* threadGroup)
{
    bool fShutdown = ShutdownRequested();
    // Tell the main threads to shutdown.
    while (!fShutdown)
    {
        MilliSleep(200);
        fShutdown = ShutdownRequested();
    }
    if (threadGroup)
    {
        Interrupt(*threadGroup);
        threadGroup->join_all();
    }
}

bool AppInitServers(boost::thread_group& threadGroup)
{
    RPCServer::OnStarted(&OnRPCStarted);
    RPCServer::OnStopped(&OnRPCStopped);
    RPCServer::OnPreCommand(&OnRPCPreCommand);
    if (!InitHTTPServer())
        return false;
    if (!StartRPC())
        return false;
    if (!StartHTTPRPC())
        return false;
    //if (GetBoolArg("-rest", DEFAULT_REST_ENABLE) && !StartREST())
    //    return false;
    if (!StartHTTPServer())
        return false;

    return true;
}

