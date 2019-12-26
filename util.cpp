
#include "util.h"
#include "sync.h"
#include "utilstrencodings.h"

#include <algorithm>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/foreach.hpp>
#include <boost/program_options/detail/config_file.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/thread.hpp>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/conf.h>

//#include <pthread.h>
//#include <pthread_np.h>
#include <sys/prctl.h>


// Work around clang compilation problem in Boost 1.46:
// /usr/include/boost/program_options/detail/config_file.hpp:163:17: error: call to function 'to_internal' that is neither visible in the template definition nor found by argument-dependent lookup
// See also: http://stackoverflow.com/questions/10020179/compilation-fail-in-boost-librairies-program-options
//           http://clang.debian.net/status.php?version=3.0&key=CANNOT_FIND_FUNCTION
namespace boost {

    namespace program_options {
        std::string to_internal(const std::string&);
    }

} // namespace boost

using namespace std;


CCriticalSection cs_args;
map<string, string> mapArgs;
static map<string, vector<string> > _mapMultiArgs;
const map<string, vector<string> >& mapMultiArgs = _mapMultiArgs;
bool fDebug = false;
bool fPrintToConsole = false;
bool fPrintToDebugLog = true;

bool fLogTimestamps = DEFAULT_LOGTIMESTAMPS;
bool fLogTimeMicros = DEFAULT_LOGTIMEMICROS;
bool fLogIPs = DEFAULT_LOGIPS;
std::atomic<bool> fReopenDebugLog(false);


/**
 * LogPrintf() has been broken a couple of times now
 * by well-meaning people adding mutexes in the most straightforward way.
 * It breaks because it may be called by global destructors during shutdown.
 * Since the order of destruction of static/global objects is undefined,
 * defining a mutex as a global object doesn't work (the mutex gets
 * destroyed, and then some later destructor calls OutputDebugStringF,
 * maybe indirectly, and you get a core dump at shutdown trying to lock
 * the mutex).
 */

static boost::once_flag debugPrintInitFlag = BOOST_ONCE_INIT;

/**
 * We use boost::call_once() to make sure mutexDebugLog and
 * vMsgsBeforeOpenLog are initialized in a thread-safe manner.
 *
 * NOTE: fileout, mutexDebugLog and sometimes vMsgsBeforeOpenLog
 * are leaked on exit. This is ugly, but will be cleaned up by
 * the OS/libc. When the shutdown sequence is fully audited and
 * tested, explicit destruction of these objects can be implemented.
 */
static FILE* fileout = NULL;
static boost::mutex* mutexDebugLog = NULL;
static list<string> *vMsgsBeforeOpenLog;
static int64_t nMockTime = 0; //!< For unit testing

int64_t GetTimeMicros()
{
    int64_t now = (boost::posix_time::microsec_clock::universal_time() -
                   boost::posix_time::ptime(boost::gregorian::date(1970,1,1))).total_microseconds();
    assert(now > 0);
    return now;
}

/** Return a time useful for the debug log */
int64_t GetLogTimeMicros()
{
    if (nMockTime) return nMockTime*1000000;

    return GetTimeMicros();
}

void MilliSleep(int64_t n)
{
    boost::this_thread::sleep_for(boost::chrono::milliseconds(n));
}

std::string DateTimeStrFormat(const char* pszFormat, int64_t nTime)
{
    static std::locale classic(std::locale::classic());
    // std::locale takes ownership of the pointer
    std::locale loc(classic, new boost::posix_time::time_facet(pszFormat));
    std::stringstream ss;
    ss.imbue(loc);
    ss << boost::posix_time::from_time_t(nTime);
    return ss.str();
}

static int FileWriteStr(const std::string &str, FILE *fp)
{
    return fwrite(str.data(), 1, str.size(), fp);
}

static void DebugPrintInit()
{
    assert(mutexDebugLog == NULL);
    mutexDebugLog = new boost::mutex();
    vMsgsBeforeOpenLog = new list<string>;
}

void OpenDebugLog()
{
    boost::call_once(&DebugPrintInit, debugPrintInitFlag);
    boost::mutex::scoped_lock scoped_lock(*mutexDebugLog);

    assert(fileout == NULL);
    assert(vMsgsBeforeOpenLog);
    boost::filesystem::path pathDebug = "debug.log";
    fileout = fopen(pathDebug.string().c_str(), "a");
    if (fileout) {
        setbuf(fileout, NULL); // unbuffered
        // dump buffered messages from before we opened the log
        while (!vMsgsBeforeOpenLog->empty()) {
            FileWriteStr(vMsgsBeforeOpenLog->front(), fileout);
            vMsgsBeforeOpenLog->pop_front();
        }
    }

    delete vMsgsBeforeOpenLog;
    vMsgsBeforeOpenLog = NULL;
}

bool LogAcceptCategory(const char* category)
{
    if (category != NULL)
    {
        if (!fDebug)
            return false;

        // Give each thread quick access to -debug settings.
        // This helps prevent issues debugging global destructors,
        // where mapMultiArgs might be deleted before another
        // global destructor calls LogPrint()
        static boost::thread_specific_ptr<set<string> > ptrCategory;
        if (ptrCategory.get() == NULL)
        {
            if (mapMultiArgs.count("-debug")) {
                const vector<string>& categories = mapMultiArgs.at("-debug");
                ptrCategory.reset(new set<string>(categories.begin(), categories.end()));
                // thread_specific_ptr automatically deletes the set when the thread ends.
            } else
                ptrCategory.reset(new set<string>());
            
        }
        const set<string>& setCategories = *ptrCategory.get();

        // if not debugging everything and not debugging specific category, LogPrint does nothing.
        if (setCategories.count(string("")) == 0 &&
            setCategories.count(string("1")) == 0 &&
            setCategories.count(string(category)) == 0)
            return false;
    }
    return true;
}

/**
 * fStartedNewLine is a state variable held by the calling context that will
 * suppress printing of the timestamp when multiple calls are made that don't
 * end in a newline. Initialize it to true, and hold it, in the calling context.
 */
static std::string LogTimestampStr(const std::string &str, std::atomic_bool *fStartedNewLine)
{
    string strStamped;

    if (!fLogTimestamps)
        return str;

    if (*fStartedNewLine) {
        int64_t nTimeMicros = GetLogTimeMicros();
        strStamped = DateTimeStrFormat("%Y-%m-%d %H:%M:%S", nTimeMicros/1000000);
        if (fLogTimeMicros)
            strStamped += strprintf(".%06d", nTimeMicros%1000000);
        strStamped += ' ' + str;
    } else
        strStamped = str;

    if (!str.empty() && str[str.size()-1] == '\n')
        *fStartedNewLine = true;
    else
        *fStartedNewLine = false;

    return strStamped;
}

int LogPrintStr(const std::string &str)
{
    namespace fs = boost::filesystem;
    int ret = 0; // Returns total number of characters written
    static std::atomic_bool fStartedNewLine(true);

    string strTimestamped = LogTimestampStr(str, &fStartedNewLine);

    if (fPrintToConsole)
    {
        // print to console
        ret = fwrite(strTimestamped.data(), 1, strTimestamped.size(), stdout);
        fflush(stdout);
    }
    else if (fPrintToDebugLog)
    {
        boost::call_once(&DebugPrintInit, debugPrintInitFlag);
        boost::mutex::scoped_lock scoped_lock(*mutexDebugLog);

        // buffer if we haven't opened the log yet
        if (fileout == NULL) {
            assert(vMsgsBeforeOpenLog);
            ret = strTimestamped.length();
            vMsgsBeforeOpenLog->push_back(strTimestamped);
        }
        else
        {
            // reopen the log file, if requested
            if (fReopenDebugLog) {
                fReopenDebugLog = false;
                //boost::filesystem::path pathDebug = GetDataDir() / "debug.log";
                boost::filesystem::path pathDebug = fs::system_complete("debug.log");
                if (freopen(pathDebug.string().c_str(),"a",fileout) != NULL)
                    setbuf(fileout, NULL); // unbuffered
            }

            ret = FileWriteStr(strTimestamped, fileout);
        }
    }
    return ret;
}

/** Interpret string as boolean, for argument parsing */
static bool InterpretBool(const std::string& strValue)
{
    if (strValue.empty())
        return true;
    return (atoi(strValue) != 0);
}

/** Turn -noX into -X=0 */
static void InterpretNegativeSetting(std::string& strKey, std::string& strValue)
{
    if (strKey.length()>3 && strKey[0]=='-' && strKey[1]=='n' && strKey[2]=='o')
    {
        strKey = "-" + strKey.substr(3);
        strValue = InterpretBool(strValue) ? "0" : "1";
    }
}

void ParseParameters(int argc, const char* const argv[])
{
    LOCK(cs_args);
    mapArgs.clear();
    _mapMultiArgs.clear();

    for (int i = 1; i < argc; i++)
    {
        std::string str(argv[i]);
        std::string strValue;
        size_t is_index = str.find('=');
        if (is_index != std::string::npos)
        {
            strValue = str.substr(is_index+1);
            str = str.substr(0, is_index);
        }
#ifdef WIN32
        boost::to_lower(str);
        if (boost::algorithm::starts_with(str, "/"))
            str = "-" + str.substr(1);
#endif

        if (str[0] != '-')
            break;

        // Interpret --foo as -foo.
        // If both --foo and -foo are set, the last takes effect.
        if (str.length() > 1 && str[1] == '-')
            str = str.substr(1);
        InterpretNegativeSetting(str, strValue);

        mapArgs[str] = strValue;
        _mapMultiArgs[str].push_back(strValue);
    }
}

bool IsArgSet(const std::string& strArg)
{
    LOCK(cs_args);
    return mapArgs.count(strArg);
}

std::string GetArg(const std::string& strArg, const std::string& strDefault)
{
    LOCK(cs_args);
    if (mapArgs.count(strArg))
        return mapArgs[strArg];
    return strDefault;
}

int64_t GetArg(const std::string& strArg, int64_t nDefault)
{
    LOCK(cs_args);
    if (mapArgs.count(strArg))
        return atoi64(mapArgs[strArg]);
    return nDefault;
}

bool GetBoolArg(const std::string& strArg, bool fDefault)
{
    LOCK(cs_args);
    if (mapArgs.count(strArg))
        return InterpretBool(mapArgs[strArg]);
    return fDefault;
}

bool SoftSetArg(const std::string& strArg, const std::string& strValue)
{
    LOCK(cs_args);
    if (mapArgs.count(strArg))
        return false;
    mapArgs[strArg] = strValue;
    return true;
}

bool SoftSetBoolArg(const std::string& strArg, bool fValue)
{
    if (fValue)
        return SoftSetArg(strArg, std::string("1"));
    else
        return SoftSetArg(strArg, std::string("0"));
}

void ForceSetArg(const std::string& strArg, const std::string& strValue)
{
    LOCK(cs_args);
    mapArgs[strArg] = strValue;
}

void RenameThread(const char* name)
{
// #if defined(PR_SET_NAME)
//     // Only the first 15 characters are used (16 - NUL terminator)
     ::prctl(PR_SET_NAME, name, 0, 0, 0);
// #elif (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
//    pthread_set_name_np(pthread_self(), name);

// #elif defined(MAC_OSX)
//     pthread_setname_np(name);
// #else
//     // Prevent warnings for unused parameters...
//     (void)name;
// #endif
}

boost::filesystem::path GetConfigFile(const std::string& confPath)
{
    boost::filesystem::path pathConfigFile(confPath);
    if (!pathConfigFile.is_complete())
        printf("Open config file error[%s]\n", confPath.c_str());
        //pathConfigFile = GetDataDir(false) / pathConfigFile;

    return pathConfigFile;
}

void ReadConfigFile(const std::string& confPath)
{
    boost::filesystem::ifstream streamConfig(GetConfigFile(confPath));
    if (!streamConfig.good())
        return; // No bitcoin.conf file is OK

    {
        LOCK(cs_args);
        set<string> setOptions;
        setOptions.insert("*");

        for (boost::program_options::detail::config_file_iterator it(streamConfig, setOptions), end; it != end; ++it)
        {
            // Don't overwrite existing settings so command line settings override bitcoin.conf
            string strKey = string("-") + it->string_key;
            string strValue = it->value[0];
            InterpretNegativeSetting(strKey, strValue);
            if (mapArgs.count(strKey) == 0)
                mapArgs[strKey] = strValue;
            _mapMultiArgs[strKey].push_back(strValue);
        }

    }
}