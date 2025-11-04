# Nimbus
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  stint,
  unittest2,
  eth/common/[addresses, base, hashes, headers, receipts, times],
  results,
  ../execution_chain/common/[eip_constants, evmforks],
  ../execution_chain/constants,
  ../execution_chain/utils/[ssz_helpers, utils],
  eth/common/eth_types_rlp as rlp_hashes

suite "EIP-7919 system logs and hashing":
  proc sampleLog(): Log =
    var log: Log
    log.address = SYSTEM_ADDRESS
    log.topics = @[
      Topic(EIP7708Magic),
      addressToTopic(address"0x00000000000000000000000000000000000000aa"),
      addressToTopic(address"0x00000000000000000000000000000000000000bb")
    ]
    log.data = @[byte 0x01, 0x02, 0x03, 0x04]
    log

  proc sampleHeader(): Header =
    let
      parent = hash32"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      ommers = hash32"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      state = hash32"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
      txRoot = hash32"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
      receipts = hash32"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
      withdraw = hash32"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      beacon = hash32"0x1111111111111111111111111111111111111111111111111111111111111111"
      requests = hash32"0x2222222222222222222222222222222222222222222222222222222222222222"
    Header(
      parentHash: parent,
      ommersHash: ommers,
      coinbase: address"0x00000000000000000000000000000000000000cc",
      stateRoot: Root(state.data),
      transactionsRoot: Root(txRoot.data),
      receiptsRoot: Root(receipts.data),
      logsBloom: default(Bloom),
      difficulty: 0.u256,
      number: 1'u64,
      gasLimit: GasInt(30_000_000),
      gasUsed: GasInt(21_000),
      timestamp: EthTime(1),
      extraData: @[],
      mixHash: default(Bytes32),
      nonce: default(Bytes8),
      baseFeePerGas: Opt.some(1.u256),
      withdrawalsRoot: Opt.some(withdraw),
      blobGasUsed: Opt.some(0'u64),
      excessBlobGas: Opt.some(0'u64),
      parentBeaconBlockRoot: Opt.some(beacon),
      requestsHash: Opt.some(requests)
    )

  test "SSZ system logs root includes EIP-7708 transfer log":
    let log = sampleLog()
    let root = sszCalcSystemLogsRoot(@[log])
    check root != default(Root)

  test "computeBlockHash switches to SSZ after EIP-7919":
    let log = sampleLog()
    let sysRoot = sszCalcSystemLogsRoot(@[log])

    var preHeader = sampleHeader()
    preHeader.systemLogsRoot = Opt.none(Hash32)
    let rlpHash = rlp_hashes.computeBlockHash(preHeader)
    check computeBlockHash(preHeader, FkAmsterdam) == rlpHash

    var postHeader = sampleHeader()
    postHeader.systemLogsRoot = Opt.some(Hash32(sysRoot.data))
    let sszHash = sszCalcBlockHash(postHeader)
    check computeBlockHash(postHeader, FkEip7919) == sszHash
