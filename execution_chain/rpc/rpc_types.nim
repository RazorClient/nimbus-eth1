# Nimbus
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import
  eth/common/block_access_lists,
  web3/[eth_api_types, conversions],
  ../beacon/web3_eth_conv

export eth_api_types, web3_eth_conv

type
  FilterLog* = eth_api_types.LogObject

  # BlockTag instead of BlockId:
  # prevent type clash with eth2 BlockId in portal/verified_proxy
  BlockTag* = eth_api_types.RtBlockIdentifier


proc writeValue*[F: EthJson | EthRpcJson](
    w: var JsonWriter[F], val: BlockAccessIndex
) {.raises: [IOError].} =
  w.writeValue(val.uint64)

proc readValue*[F: EthJson | EthRpcJson](
    r: var JsonReader[F], val: var BlockAccessIndex
) {.raises: [SerializationError, IOError].} =
  val = BlockAccessIndex(r.readValue(uint64))

# Block access list json serialization
AccountChanges.useDefaultSerializationIn EthJson
AccountChanges.useDefaultSerializationIn EthRpcJson
SlotChanges.useDefaultSerializationIn EthJson
SlotChanges.useDefaultSerializationIn EthRpcJson
StorageChange.useDefaultSerializationIn EthJson
StorageChange.useDefaultSerializationIn EthRpcJson
BalanceChange.useDefaultSerializationIn EthJson
BalanceChange.useDefaultSerializationIn EthRpcJson
NonceChange.useDefaultSerializationIn EthJson
NonceChange.useDefaultSerializationIn EthRpcJson
CodeChange.useDefaultSerializationIn EthJson
CodeChange.useDefaultSerializationIn EthRpcJson
