#ifndef WEALEDGER_NETBASE_H
#define WEALEDGER_NETBASE_H

#include <stdint.h>
#include <string>
#include <vector>

#include "netaddress.h"

void SplitHostPort(std::string in, int &portOut, std::string &hostOut);
bool LookupHost(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions, bool fAllowLookup);
bool LookupHost(const char *pszName, CNetAddr& addr, bool fAllowLookup);
bool Lookup(const char *pszName, CService& addr, int portDefault, bool fAllowLookup);
bool Lookup(const char *pszName, std::vector<CService>& vAddr, int portDefault, bool fAllowLookup, unsigned int nMaxSolutions);
CService LookupNumeric(const char *pszName, int portDefault = 0);
bool LookupSubNet(const char *pszName, CSubNet& subnet);



#endif  //WEALEDGER_NETBASE_H