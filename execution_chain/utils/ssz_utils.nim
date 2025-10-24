
import
  eth/common/[transactions, receipts, addresses, hashes, blocks],
  eth/ssz/[receipts_ssz, transaction_ssz, blocks_ssz, sszcodec],
  ssz_serialization/merkleization

# SSZ helper functions for EIP-6465 (transactions), EIP-6466 (receipts),
# and EIP-7807 (SSZ block structure)
proc sszCalcTxRoot*(transactions: openArray[transactions.Transaction]): Root {.raises: [ValueError].} =

  if transactions.len == 0:
    return default(Root)

  # Convert RLP transactions to SSZ transactions
  var sszTxs: seq[transaction_ssz.Transaction]
  for tx in transactions:
    sszTxs.add(toSszTx(tx))

  # Compute SSZ merkle root
  Root(sszTxs.hash_tree_root().data)

proc sszCalcReceiptsRoot*(
    receipts: openArray[StoredReceipt]
): Root =

  if receipts.len == 0:
    return default(Root)

  var sszReceipts: seq[receipts_ssz.Receipt]

  for rec in receipts:
    # Convert logs to SSZ format
    var sszLogs: seq[receipts_ssz.Log]
    for log in rec.logs:
      var topics: seq[Bytes32]
      for topic in log.topics:
          topics.add(cast[Bytes32](topic))

      sszLogs.add(receipts_ssz.Log(
        address: log.address,
        topics: List[Bytes32, 4](topics),
        data: log.data
      ))

    # Determine receipt kind and create appropriate SSZ receipt based on eip7807ReceiptType
    let sszReceipt = case rec.eip7807ReceiptType
    of Eip7807SetCode:
      let setCodeRec = receipts_ssz.SetCodeReceipt(
        `from`: rec.origin,
        gas_used: rec.txGasUsed,
        contract_address: rec.contactAddress,
        logs: sszLogs,
        status: rec.status,
        authorities: rec.authorities
      )
      receipts_ssz.Receipt(kind: rSetCode, setcode: setCodeRec)

    of Eip7807Create:
      let createRec = receipts_ssz.CreateReceipt(
        `from`: rec.origin,
        gas_used: rec.txGasUsed,
        contract_address: rec.contactAddress,
        logs: sszLogs,
        status: rec.status
      )
      receipts_ssz.Receipt(kind: rCreate, create: createRec)

    of Eip7807Basic:
      let basicRec = receipts_ssz.BasicReceipt(
        `from`: rec.origin,
        gas_used: rec.txGasUsed,
        contract_address: default(Address),
        logs: sszLogs,
        status: rec.status
      )
      receipts_ssz.Receipt(kind: rBasic, basic: basicRec)

    sszReceipts.add(sszReceipt)
  Root(sszReceipts.hash_tree_root().data)

proc sszCalcWithdrawalsRoot*(withdrawals: openArray[blocks.Withdrawal]): Root =
  if withdrawals.len == 0:
    return default(Root)
  var sszW: seq[blocks_ssz.Withdrawal] = @[]
  sszW.setLen(withdrawals.len)
  for i, w in withdrawals:
    sszW[i] = toSszWithdrawal(w)
  Root(sszW.hash_tree_root().data)

proc sszCalcSystemLogsRoot*(logs: openArray[receipts.Log]): Root =
  if logs.len == 0:
    return default(Root)

  var sszLogs: seq[receipts_ssz.Log]
  for log in logs:
    var topics: seq[Bytes32]
    for topic in log.topics:
      topics.add(cast[Bytes32](topic))
    sszLogs.add(receipts_ssz.Log(
      address: log.address,
      topics: List[Bytes32, 4](topics),
      data: log.data
    ))

  Root(sszLogs.hash_tree_root().data)
