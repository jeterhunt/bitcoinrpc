#ifndef WEALEDGERSSL_INIT_H
#define WEALEDGERSSL_INIT_H


namespace boost
{
class thread_group;
} // namespace boost

void Shutdown();

bool AppInit(int argc, char* argv[]);

void StartShutdown();
bool ShutdownRequested();
bool AppInitServers(boost::thread_group& threadGroup);
void WaitForShutdown(boost::thread_group* threadGroup);


#endif