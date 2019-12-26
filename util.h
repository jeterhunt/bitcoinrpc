#ifndef WEALEDGERSSL_UTIL_H
#define WEALEDGERSSL_UTIL_H

#include "tinyformat.h"

#include <atomic>
#include <exception>
#include <map>
#include <stdint.h>
#include <string>
#include <vector>

#include <boost/filesystem/path.hpp>
#include <boost/signals2/signal.hpp>
#include <boost/thread/exceptions.hpp>

static const bool DEFAULT_LOGTIMEMICROS = false;
static const bool DEFAULT_LOGIPS        = false;
static const bool DEFAULT_LOGTIMESTAMPS = true;


extern const std::map<std::string, std::vector<std::string> >& mapMultiArgs;
extern bool fDebug;
extern bool fPrintToConsole;
extern bool fPrintToDebugLog;

extern bool fLogTimestamps;
extern bool fLogTimeMicros;
extern bool fLogIPs;
extern std::atomic<bool> fReopenDebugLog;


/** Return true if log accepts specified category */
bool LogAcceptCategory(const char* category);
/** Send a string to the log output */
int LogPrintStr(const std::string &str);

void SetDebug(bool enable, const std::vector<std::string>& options);

#define LogPrint(category, ...) do { \
    if (LogAcceptCategory((category))) { \
        LogPrintStr(tfm::format(__VA_ARGS__)); \
    } \
} while(0)

#define LogPrintf(...) do { \
    LogPrintStr(tfm::format(__VA_ARGS__)); \
} while(0)

template<typename... Args>
bool error(const char* fmt, const Args&... args)
{
    LogPrintStr("ERROR: " + tfm::format(fmt, args...) + "\n");
    return false;
}

int64_t GetTimeMicros();
int64_t GetLogTimeMicros();
void MilliSleep(int64_t n);
std::string DateTimeStrFormat(const char* pszFormat, int64_t nTime);

void ParseParameters(int argc, const char*const argv[]);

/**
 * Return true if the given argument has been manually set
 *
 * @param strArg Argument to get (e.g. "-foo")
 * @return true if the argument has been set
 */
bool IsArgSet(const std::string& strArg);

/**
 * Return string argument or default value
 *
 * @param strArg Argument to get (e.g. "-foo")
 * @param default (e.g. "1")
 * @return command-line argument or default value
 */
std::string GetArg(const std::string& strArg, const std::string& strDefault);

/**
 * Return integer argument or default value
 *
 * @param strArg Argument to get (e.g. "-foo")
 * @param default (e.g. 1)
 * @return command-line argument (0 if invalid number) or default value
 */
int64_t GetArg(const std::string& strArg, int64_t nDefault);

/**
 * Return boolean argument or default value
 *
 * @param strArg Argument to get (e.g. "-foo")
 * @param default (true or false)
 * @return command-line argument or default value
 */
bool GetBoolArg(const std::string& strArg, bool fDefault);

/**
 * Set an argument if it doesn't already have a value
 *
 * @param strArg Argument to set (e.g. "-foo")
 * @param strValue Value (e.g. "1")
 * @return true if argument gets set, false if it already had a value
 */
bool SoftSetArg(const std::string& strArg, const std::string& strValue);

/**
 * Set a boolean argument if it doesn't already have a value
 *
 * @param strArg Argument to set (e.g. "-foo")
 * @param fValue Value (e.g. false)
 * @return true if argument gets set, false if it already had a value
 */
bool SoftSetBoolArg(const std::string& strArg, bool fValue);

// Forces a arg setting, used only in testing
void ForceSetArg(const std::string& strArg, const std::string& strValue);

void RenameThread(const char* name);

boost::filesystem::path GetConfigFile(const std::string& confPath);
void ReadConfigFile(const std::string& confPath);
void OpenDebugLog();


#endif //WEALEDGERSSL_UTIL_H