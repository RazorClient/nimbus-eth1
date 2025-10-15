
import
  eth/common/[transactions, receipts, addresses, hashes, blocks],
  eth/ssz/[receipts_ssz, transaction_ssz, blocks_ssz, sszcodec],
  ssz_serialization/merkleization,
  ../common/evmforks,
   ./receipts_context

export receipts_ssz, transaction_ssz, blocks_ssz, sszcodec

# SSZ helper functions for EIP-6465 (transactions), EIP-6466 (receipts),
# and EIP-7807 (SSZ block structure)

proc sszCalcTxRoot*(transactions: openArray[Transaction]): Root =

  if transactions.len == 0:
    return default(Root)

  # Convert RLP transactions to SSZ transactions
  var sszTxs: seq[eth_ssz.Transaction]
  for tx in transactions:
    sszTxs.add(toSszTx(tx))

  # Compute SSZ merkle root
  sszTxs.hash_tree_root()

proc sszCalcReceiptsRoot*(
    receipts: openArray[StoredReceipt],
    contexts: openArray[ReceiptContext]
): Root =

  if receipts.len == 0:
    return default(Root)

  if receipts.len != contexts.len:
    raiseAssert("receipts and contexts length mismatch: " & $receipts.len & " != " & $contexts.len)

  var sszReceipts: seq[eth_ssz_receipts.Receipt]

  for i in 0 ..< receipts.len:
    let rec = receipts[i]
    let ctx = contexts[i]

    # Convert logs to SSZ format
    var sszLogs: seq[eth_ssz_receipts.Log]
    for log in rec.logs:
      var topics: seq[Hash32]
      for topic in log.topics:
        topics.add(cast[Hash32](topic))

      sszLogs.add(eth_ssz_receipts.Log(
        address: log.address,
        topics: List[Hash32, 4](topics),
        data: log.data
      ))

    # Determine receipt kind and create appropriate SSZ receipt
    let sszReceipt = if rec.receiptType == TxEip7702:
      let setCodeRec = eth_ssz_receipts.SetCodeReceipt(
        `from`: ctx.sender,
        gas_used: ctx.txGasUsed,
        contract_address: ctx.contractAddress,
        logs: sszLogs,
        status: rec.status,
        authorities: ctx.authorities
      )
      eth_ssz_receipts.Receipt(kind: rSetCode, setcode: setCodeRec)

    # TODO:make sure this is ok and works
    elif ctx.isCreate:
      let createRec = eth_ssz_receipts.CreateReceipt(
        `from`: ctx.sender,
        gas_used: ctx.txGasUsed,
        contract_address: ctx.contractAddress,
        logs: sszLogs,
        status: rec.status
      )
      eth_ssz_receipts.Receipt(kind: rCreate, create: createRec)

    else:
      let basicRec = eth_ssz_receipts.BasicReceipt(
        `from`: ctx.sender,
        gas_used: ctx.txGasUsed,
        contract_address: default(Address),
        logs: sszLogs,
        status: rec.status
      )
      eth_ssz_receipts.Receipt(kind: rBasic, basic: basicRec)

    sszReceipts.add(sszReceipt)
  sszReceipts.hash_tree_root()

proc sszCalcWithdrawalsRoot*(withdrawals: openArray[Withdrawal]): Root =
    if withdrawals.len == 0:
    return default(Root)

proc sszCalcSystemLogsRoot*(logs: openArray[Log]): Root =
  if logs.len == 0:
    return default(Root)

  var sszLogs: seq[eth_ssz_receipts.Log]
  for log in logs:
    var topics: seq[Hash32]
    for topic in log.topics:
      topics.add(cast[Hash32](topic))
    sszLogs.add(eth_ssz_receipts.Log(
      address: log.address,
      topics: List[Hash32, 4](topics),
      data: log.data
    ))

  sszLogs.hash_tree_root()
