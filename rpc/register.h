

#ifndef WEALEDGER_RPCREGISTER_H
#define WEALEDGER_RPCREGISTER_H

/** These are in one header file to avoid creating tons of single-function
 * headers for everything under src/rpc/ */
class CRPCTable;

/** Register block chain RPC commands */
void RegisterMainGMCRYPTOCommands(CRPCTable &tableRPC);
// /** Register P2P networking RPC commands */
// void RegisterNetRPCCommands(CRPCTable &tableRPC);
// /** Register miscellaneous RPC commands */
// void RegisterMiscRPCCommands(CRPCTable &tableRPC);
// /** Register mining RPC commands */
// void RegisterMiningRPCCommands(CRPCTable &tableRPC);
// /** Register raw transaction RPC commands */
// void RegisterRawTransactionRPCCommands(CRPCTable &tableRPC);
// /** Register smart contract RPC commands */
// void RegisterSmartContractRPCCommands(CRPCTable &tableRPC);

static inline void RegisterAllCoreRPCCommands(CRPCTable &t)
{
    RegisterMainGMCRYPTOCommands(t);
    // RegisterNetRPCCommands(t);
    // RegisterMiscRPCCommands(t);
    // RegisterMiningRPCCommands(t);
    // RegisterRawTransactionRPCCommands(t);
    // RegisterSmartContractRPCCommands(t);
}

#endif
