

#ifndef WEALEDGER_HTTPRPC_H
#define WEALEDGER_HTTPRPC_H

#include <string>
#include <map>

class HTTPRequest;

/** Start HTTP RPC subsystem.
 * Precondition; HTTP and RPC has been started.
 */
bool StartHTTPRPC();
/** Interrupt HTTP RPC subsystem.
 */ 
void InterruptHTTPRPC();
/** Stop HTTP RPC subsystem.
 * Precondition; HTTP and RPC has been stopped.
 */
void StopHTTPRPC();

// /** Start HTTP REST subsystem.
//  * Precondition; HTTP and RPC has been started.
//  */
// bool StartREST();
// /** Interrupt RPC REST subsystem.
//  */
// void InterruptREST();
// /** Stop HTTP REST subsystem.
//  * Precondition; HTTP and RPC has been stopped.
//  */
// void StopREST();

#endif
