# Nimbus
# Copyright (c) 2022-2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
#    http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or
#    http://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

import
  std/[json, strutils],
  eth/[common, keys],
  eth/trie/trie_defs,
  stint,
  stew/byteutils,
  ../../nimbus/transaction,
  ../../nimbus/db/ledger,
  ../../nimbus/common/chain_config

template fromJson(T: type EthAddress, n: JsonNode): EthAddress =
  EthAddress.fromHex(n.getStr)

proc fromJson(T: type UInt256, n: JsonNode): UInt256 =
  # stTransactionTest/ValueOverflow.json
  # prevent parsing exception and subtitute it with max uint256
  let hex = n.getStr
  if ':' in hex:
    high(UInt256)
  else:
    UInt256.fromHex(hex)

template fromJson*(T: type Hash256, n: JsonNode): Hash256 =
  Hash32(hexToByteArray(n.getStr, 32))

proc fromJson(T: type Blob, n: JsonNode): Blob =
  let hex = n.getStr
  if hex.len == 0:
    @[]
  else:
    hexToSeqByte(hex)

template fromJson(T: type uint64, n: JsonNode): uint64 =
  fromHex[AccountNonce](n.getStr)

template fromJson(T: type EthTime, n: JsonNode): EthTime =
  EthTime(fromHex[uint64](n.getStr))

proc fromJson(T: type PrivateKey, n: JsonNode): PrivateKey =
  var secretKey = n.getStr
  removePrefix(secretKey, "0x")
  PrivateKey.fromHex(secretKey).tryGet()

proc fromJson(T: type AccessList, n: JsonNode): AccessList =
  if n.kind == JNull:
    return

  for x in n:
    var ap = AccessPair(
      address: EthAddress.fromJson(x["address"])
    )
    let sks = x["storageKeys"]
    for sk in sks:
      ap.storageKeys.add Bytes32.fromHex(sk.getStr)
    result.add ap

proc fromJson(T: type VersionedHashes, list: JsonNode): VersionedHashes =
  for x in list:
    result.add VersionedHash.fromHex(x.getStr)

template required(T: type, nField: string): auto =
  fromJson(T, n[nField])

template required(T: type, nField: string, index: int): auto =
  fromJson(T, n[nField][index])

template omitZero(T: type, nField: string): auto =
  if n.hasKey(nField):
    fromJson(T, n[nField])
  else:
    default(T)

template omitZero(T: type, nField: string, index: int): auto =
  if n.hasKey(nField):
    fromJson(T, n[nField][index])
  else:
    default(T)

template optional(T: type, nField: string): auto =
  if n.hasKey(nField):
    Opt.some(T.fromJson(n[nField]))
  else:
    Opt.none(T)

proc txType(n: JsonNode): TxType =
  if "blobVersionedHashes" in n:
    return TxEip4844
  if "gasPrice" notin n:
    return TxEip1559
  if "accessLists" in n:
    return TxEip2930
  TxLegacy

proc parseHeader*(n: JsonNode): BlockHeader =
  BlockHeader(
    coinbase   : required(EthAddress, "currentCoinbase"),
    difficulty : required(DifficultyInt, "currentDifficulty"),
    number     : required(BlockNumber, "currentNumber"),
    gasLimit   : required(GasInt, "currentGasLimit"),
    timestamp  : required(EthTime, "currentTimestamp"),
    stateRoot  : emptyRlpHash,
    mixHash    : omitZero(Hash256, "currentRandom"),
    baseFeePerGas  : optional(UInt256, "currentBaseFee"),
    withdrawalsRoot: optional(Hash256, "currentWithdrawalsRoot"),
    excessBlobGas  : optional(uint64, "currentExcessBlobGas"),
    parentBeaconBlockRoot: optional(Hash256, "currentBeaconRoot"),
  )

proc parseParentHeader*(n: JsonNode): BlockHeader =
  BlockHeader(
    stateRoot: emptyRlpHash,
    excessBlobGas: optional(uint64, "parentExcessBlobGas"),
    blobGasUsed: optional(uint64, "parentBlobGasUsed"),
  )

proc parseTx*(n: JsonNode, dataIndex, gasIndex, valueIndex: int): Transaction =
  var tx = Transaction(
    txType  : txType(n),
    nonce   : required(AccountNonce, "nonce"),
    gasLimit: required(GasInt, "gasLimit", gasIndex),
    value   : required(UInt256, "value", valueIndex),
    payload : required(Blob, "data", dataIndex),
    chainId : ChainId(1),
    gasPrice: omitZero(GasInt, "gasPrice"),
    maxFeePerGas        : omitZero(GasInt, "maxFeePerGas"),
    accessList          : omitZero(AccessList, "accessLists", dataIndex),
    maxPriorityFeePerGas: omitZero(GasInt, "maxPriorityFeePerGas"),
    maxFeePerBlobGas    : omitZero(UInt256, "maxFeePerBlobGas"),
    versionedHashes     : omitZero(VersionedHashes, "blobVersionedHashes")
  )

  let rawTo = n["to"].getStr
  if rawTo != "":
    tx.to = Opt.some(EthAddress.fromHex(rawTo))

  let secretKey = required(PrivateKey, "secretKey")
  signTransaction(tx, secretKey, tx.chainId, false)

proc parseTx*(txData, index: JsonNode): Transaction =
  let
    dataIndex = index["data"].getInt
    gasIndex  = index["gas"].getInt
    valIndex  = index["value"].getInt
  parseTx(txData, dataIndex, gasIndex, valIndex)

proc setupStateDB*(wantedState: JsonNode, stateDB: LedgerRef) =
  for ac, accountData in wantedState:
    let account = Address.fromHex(ac)
    for slot, value in accountData{"storage"}:
      stateDB.setStorage(account, fromHex(UInt256, slot), fromHex(UInt256, value.getStr))

    stateDB.setNonce(account, fromJson(AccountNonce, accountData["nonce"]))
    stateDB.setCode(account, fromJson(Blob, accountData["code"]))
    stateDB.setBalance(account, fromJson(UInt256, accountData["balance"]))

iterator postState*(node: JsonNode): (EthAddress, GenesisAccount) =
  for ac, accountData in node:
    let account = EthAddress.fromHex(ac)
    var ga = GenesisAccount(
      nonce  : fromJson(AccountNonce, accountData["nonce"]),
      code   : fromJson(Blob, accountData["code"]),
      balance: fromJson(UInt256, accountData["balance"]),
    )

    for slot, value in accountData{"storage"}:
      ga.storage[fromHex(UInt256, slot)] = fromHex(UInt256, value.getStr)

    yield (account, ga)
