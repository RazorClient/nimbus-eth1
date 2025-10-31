import
  std/[sequtils],
  eth/common/[transactions, receipts, blocks],
  eth/ssz/sszcodec,
  eth/ssz/blocks_ssz,
  eth/ssz/transaction_ssz as ssz_tx,
  eth/ssz/receipts_ssz as ReceiptsSsz,
  ssz_serialization,
  ssz_serialization/merkleization

from eth/ssz/transaction_builder import TxBuildError

export ssz_serialization, sszcodec

# SSZ helper functions for EIP-6465 (transactions), EIP-6466 (receipts), and EIP-7807 (SSZ block structure)
proc sszCalcTxRoot*(txs: openArray[transactions.Transaction]): Root =
  if txs.len == 0:
    return default(Root)

  # Convert RLP transactions to SSZ transactions
  var sszTxs = newSeqOfCap[ssz_tx.Transaction](txs.len)
  for tx in txs:
    try:
      sszTxs.add(toSszTx(tx))
    except ValueError as e:
      raiseAssert("SSZ transaction conversion failed: " & e.msg)
    except TxBuildError as e:
      raiseAssert("SSZ transaction build failed: " & e.msg)

  Root(sszTxs.hash_tree_root().data)

proc sszCalcReceiptsRoot*(receipts: openArray[StoredReceipt]): Root =
  if receipts.len == 0:
    return default(Root)

  var sszReceipts: seq[ReceiptsSsz.Receipt]

  for rec in receipts:
    doAssert( rec.receiptType == Eip7807Receipt,"EIP-7807 receipt required when computing SSZ receipts root")
    # Convert logs to SSZ format
    var sszLogs: seq[ReceiptsSsz.Log]
    for log in rec.logs:
      let limitedTopics =
        log.topics[0 ..< min(log.topics.len, ReceiptsSsz.MAX_TOPICS_PER_LOG)]
          .mapIt(Bytes32(it))
      let topicsList = List[Bytes32, ReceiptsSsz.MAX_TOPICS_PER_LOG].init(limitedTopics)
      sszLogs.add(ReceiptsSsz.Log(
        address: log.address,
        topics: topicsList,
        data: log.data
      ))

    let sender = rec.origin
    let gasUsed = rec.txGasUsed
    let receiptVariant =
      case rec.eip7807ReceiptType
      of Eip7807SetCode:
        ReceiptsSsz.Receipt(
          kind: ReceiptsSsz.rSetCode,
          setcode: ReceiptsSsz.SetCodeReceipt(
            `from`: sender,
            gas_used: gasUsed,
            contract_address: rec.contactAddress,
            logs: sszLogs,
            status: rec.status,
            authorities: rec.authorities
          )
        )
      of Eip7807Create:
        ReceiptsSsz.Receipt(
          kind: ReceiptsSsz.rCreate,
          create: ReceiptsSsz.CreateReceipt(
            `from`: sender,
            gas_used: gasUsed,
            contract_address: rec.contactAddress,
            logs: sszLogs,
            status: rec.status
          )
        )
      of Eip7807Basic:
        ReceiptsSsz.Receipt(
          kind: ReceiptsSsz.rBasic,
          basic: ReceiptsSsz.BasicReceipt(
            `from`: sender,
            gas_used: gasUsed,
            contract_address: default(Address),
            logs: sszLogs,
            status: rec.status
          )
        )

    sszReceipts.add(receiptVariant)

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
  ## Calculate SSZ merkle root for EIP-7799 system logs (same Log type as receipts)
  if logs.len == 0:
    return default(Root)

  var sszLogs: seq[ReceiptsSsz.Log]
  for log in logs:
    let topicsList =
      List[Bytes32, ReceiptsSsz.MAX_TOPICS_PER_LOG].init(
        log.topics[0 ..< min(log.topics.len, ReceiptsSsz.MAX_TOPICS_PER_LOG)]
          .mapIt(Bytes32(it))
      )
    sszLogs.add(ReceiptsSsz.Log(
      address: log.address,
      topics: topicsList,
      data: log.data
    ))

  Root(sszLogs.hash_tree_root().data)


proc sszCalcBlockHash*(header: headers.Header): Hash32 =
  var sszHeader: blocks_ssz.Header
  sszHeader.parent_hash = Root(header.parentHash.data)
  sszHeader.miner = header.coinbase
  sszHeader.state_root = Bytes32(header.stateRoot.data)
  sszHeader.transactions_root = Root(header.txRoot.data)
  sszHeader.receipts_root = Root(header.receiptsRoot.data)
  sszHeader.number = header.number.uint64
  sszHeader.gas_limits = blocks_ssz.GasAmounts(
    regular: header.gasLimit.uint64,
    blob: blocks_ssz.MAX_BLOB_GAS_PER_BLOCK
  )
  sszHeader.gas_used = blocks_ssz.GasAmounts(
    regular: header.gasUsed.uint64,
    blob: header.blobGasUsed.get
  )
  sszHeader.timestamp = header.timestamp.uint64
  sszHeader.extra_data = @(header.extraData)
  sszHeader.mix_hash = Bytes32(header.mixHash.data)
  sszHeader.base_fees_per_gas = blocks_ssz.BlobFeesPerGas(
    regular: header.baseFeePerGas.get.truncate(uint64),
    blob: blobBaseFee
  )
  sszHeader.withdrawals_root = Root(header.withdrawalsRoot.get.data)
  sszHeader.excess_gas = blocks_ssz.GasAmounts(
    regular: 0,  # Not used in current spec
    blob: header.excessBlobGas.get
  )
  sszHeader.parent_beacon_block_root = Root(header.parentBeaconBlockRoot.get.data)
  sszHeader.requests_hash = Bytes32(header.requestsHash.get.data)
  sszHeader.system_logs_root = Root(header.systemLogsRoot.get.data)

  Hash32(sszHeader.hash_tree_root().data)
