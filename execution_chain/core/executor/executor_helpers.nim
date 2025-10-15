# Nimbus
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
#    http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or
#    http://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

{.push raises: [].}

import
  eth/bloom,
  stew/assign2,
  ../../db/ledger,
  ../../evm/state,
  ../../evm/types,
  ../../common/common,
  ../../transaction/call_types

type
  ExecutorError* = object of CatchableError
    ## Catch and relay exception error

  # TODO: these types need to be removed
  # once eth/bloom and eth/common sync'ed
  LogsBloom = bloom.BloomFilter

# ------------------------------------------------------------------------------
# Private functions
# ------------------------------------------------------------------------------

func logsBloom(logs: openArray[Log]): LogsBloom =
  for log in logs:
    result.incl log.address
    for topic in log.topics:
      result.incl topic

# ------------------------------------------------------------------------------
# Public functions
# ------------------------------------------------------------------------------

func createBloom*(receipts: openArray[StoredReceipt]): Bloom =
  var bloom: LogsBloom
  for rec in receipts:
    bloom.value = bloom.value or logsBloom(rec.logs).value
  bloom.value.to(Bloom)

proc extractAuthorities(vmState: BaseVMState): seq[Address] =
 # Returns the list of authority addresses that had delegation code set
 # during preExecComputation
  vmState.currentTxAuthorities

proc makeReceipt*(
    vmState: BaseVMState;
    sender: Address;
    nonce: AccountNonce;
    txType: TxType;
    isCreate: bool;
    callResult: LogResult;
    previousCumulativeGas: GasInt  # For calculating per-tx gas
): StoredReceipt =
  var rec: StoredReceipt
  if vmState.com.isByzantiumOrLater(vmState.blockNumber):
    rec.isHash = false
    rec.status = vmState.status
  else:
    rec.isHash = true
    rec.hash   = vmState.ledger.getStateRoot()
    # we set the status for the t8n output consistency
    rec.status = vmState.status

  rec.receiptType = txType
  rec.cumulativeGasUsed = vmState.cumulativeGasUsed
  assign(rec.logs, callResult.logEntries)

    # Capture SSZ receipt context if post-EIP7807
  if vmState.fork >= FkEip7807:
    let txGasUsed = uint64(vmState.cumulativeGasUsed - previousCumulativeGas)
    let contractAddr = if isCreate::
      generateAddress(sender, tx.nonce)
    else:
      default(Address)
    let authorities = if tx.txType == TxEip7702:
      extractAuthorities(vmState)
    else:
      @[]

    vmState.receiptContexts.add(ReceiptContext(
      sender: sender,
      txGasUsed: txGasUsed,
      contractAddress: contractAddr,
      authorities: authorities,
      isCreate: isCreate
    ))
  rec

# ------------------------------------------------------------------------------
# End
# ------------------------------------------------------------------------------
