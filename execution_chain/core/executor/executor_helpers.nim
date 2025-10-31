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
  results,
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

proc makeReceipt*(
    vmState: BaseVMState;
    sender: Address;
    nonce: AccountNonce;
    txType: TxType;
    isCreate: bool;
    destination: Address;
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

  rec.cumulativeGasUsed = vmState.cumulativeGasUsed
  assign(rec.logs, callResult.logEntries)

  # Default to legacy behaviour unless the SSZ receipts fork is active
  if vmState.fork >= FkEip7919:
    # All post-fork stored receipts use the EIP-7807 typed format
    rec.receiptType = Eip7807Receipt

    let gasUsedDelta = vmState.cumulativeGasUsed - previousCumulativeGas
    let txGasUsed = uint64(gasUsedDelta)
    rec.txGasUsed = txGasUsed
    rec.origin = sender

    var contractAddr = default(Address)
    if isCreate:
      contractAddr =
        if callResult.contractAddress != default(Address):
          callResult.contractAddress
        else:
          generateAddress(sender, nonce)
    elif txType == TxEip7702:
      contractAddr = destination
    rec.contactAddress = contractAddr

    case txType
    of TxEip7702:
      rec.eip7807ReceiptType = Eip7807SetCode
      rec.authorities = vmState.txCtx.authorities.get(@[])
    else:
      if isCreate:
        rec.eip7807ReceiptType = Eip7807Create
      else:
        rec.eip7807ReceiptType = Eip7807Basic
      rec.authorities = @[]

    vmState.txCtx.txGasUsed = Opt.some(txGasUsed)
    if isCreate:
      vmState.txCtx.contractAddress = Opt.some(contractAddr)
    else:
      vmState.txCtx.contractAddress = Opt.none(Address)

    if txType == TxEip7702:
      vmState.txCtx.sszReceiptKind = Opt.some(SszSetCode)
    elif isCreate:
      vmState.txCtx.sszReceiptKind = Opt.some(SszCreate)
    else:
      vmState.txCtx.sszReceiptKind = Opt.some(SszBasic)
  else:
    rec.receiptType = txType
    rec.eip7807ReceiptType = Eip7807Basic
    rec.txGasUsed = 0
    rec.authorities = @[]
    rec.contactAddress = default(Address)
    rec.origin = default(Address)
    vmState.txCtx.txGasUsed = Opt.none(uint64)
    vmState.txCtx.contractAddress = Opt.none(Address)
    vmState.txCtx.sszReceiptKind = Opt.none(SszReceiptKind)
  # Authorities for non-SetCode receipts should always be empty
  if rec.eip7807ReceiptType != Eip7807SetCode and rec.authorities.len != 0:
    rec.authorities.setLen(0)

  if vmState.fork >= FkEip7919:
    if rec.eip7807ReceiptType != Eip7807SetCode:
      vmState.txCtx.authorities = Opt.none(seq[Address])

  rec

# ------------------------------------------------------------------------------
# End
# ------------------------------------------------------------------------------
