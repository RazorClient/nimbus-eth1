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
  std/[os, strformat, sequtils, strutils, times],
  ../../nimbus/core/tx_pool/[tx_desc, tx_item, tx_tabs],
  ../../nimbus/core/tx_pool/tx_tasks/[tx_recover],
  ../replay/[pp, undump_blocks_gz],
  chronicles,
  eth/common/[transactions, keys],
  stew/[byteutils,keyed_queue, sorted_set],
  stint

# Make sure that the runner can stay on public view without the need
# to import `tx_pool/*` sup-modules
export
  pp,
  tx_desc.txDB,
  tx_recover.recoverItem,
  tx_tabs.TxTabsRef,
  tx_tabs.decAccount,
  tx_tabs.dispose,
  tx_tabs.eq,
  tx_tabs.flushRejects,
  tx_tabs.ge,
  tx_tabs.gt,
  tx_tabs.incAccount,
  tx_tabs.incNonce,
  tx_tabs.le,
  tx_tabs.len,
  tx_tabs.lt,
  tx_tabs.nItems,
  tx_tabs.reassign,
  tx_tabs.reject,
  undumpBlocksGz

const
  # pretty printing
  localInfo* = block:
    var rc: array[bool,string]
    rc[true] = "L"
    rc[false] = "R"
    rc

  statusInfo* = block:
    var rc: array[TxItemStatus,string]
    rc[txItemPending] = "*"
    rc[txItemStaged] = "S"
    rc[txItemPacked] = "P"
    rc

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

proc toHex2(a: byte): string =
  # Avoids compiler warning with `toHex(2)`
  [a].toHex

proc joinXX(s: string): string =
  if s.len <= 30:
    return s
  if (s.len and 1) == 0:
    result = s[0 ..< 8]
  else:
    result = "0" & s[0 ..< 7]
  result &= "..(" & $((s.len + 1) div 2) & ").." & s[s.len-16 ..< s.len]

proc joinXX(q: seq[string]): string =
  q.join("").joinXX

proc toXX[T](s: T): string =
  s.toHex.strip(leading=true,chars={'0'}).toLowerAscii

proc toXX(q: seq[byte]): string =
  q.mapIt(it.toHex2).join(":")

proc toXX(a: Address): string =
  a.data.mapIt(it.toHex2).joinXX

proc toXX(h: Hash32): string =
  h.data.mapIt(it.toHex2).joinXX

proc toXX(v: uint64; r,s: UInt256): string =
  v.toXX & ":" & ($r).joinXX & ":" & ($s).joinXX

# ------------------------------------------------------------------------------
# Public functions,  pretty printer
# ------------------------------------------------------------------------------

proc pp*(q: seq[(Address,int)]): string =
  "[" & q.mapIt(&"{it[0].pp}:{it[1]:03d}").join(",") & "]"

proc pp*(w: TxItemStatus): string =
  ($w).replace("txItem")

proc pp*(tx: Transaction): string =
  ## Pretty print transaction (use for debugging)
  result = "(txType=" & $tx.txType

  if tx.chainId.uint64 != 0:
    result &= ",chainId=" & $tx.chainId.uint64

  result &= ",nonce=" & tx.nonce.toXX
  if tx.gasPrice != 0:
    result &= ",gasPrice=" & tx.gasPrice.toKMG
  if tx.maxPriorityFeePerGas != 0:
    result &= ",maxPrioFee=" & tx.maxPriorityFeePerGas.toKMG
  if tx.maxFeePerGas != 0:
    result &= ",maxFee=" & tx.maxFeePerGas.toKMG
  if tx.gasLimit != 0:
    result &= ",gasLimit=" & tx.gasLimit.toKMG
  if tx.to.isSome:
    result &= ",to=" & tx.to.get.toXX
  if tx.value.isZero.not:
    result &= ",value=" & tx.value.toKMG
  if 0 < tx.payload.len:
    result &= ",payload=" & tx.payload.toXX
  if 0 < tx.accessList.len:
    result &= ",accessList=" & $tx.accessList

  result &= ",VRS=" & tx.V.toXX(tx.R,tx.S)
  result &= ")"

proc pp*(w: TxItemRef): string =
  ## Pretty print item (use for debugging)
  let s = w.tx.pp
  result = "(timeStamp=" & ($w.timeStamp).replace(' ','_') &
    ",hash=" & w.itemID.toXX &
    ",status=" & w.status.pp &
    "," & s[1 ..< s.len]

proc pp*(txs: openArray[Transaction]; pfx = ""): string =
  let txt = block:
    var rc = ""
    if 0 < txs.len:
      rc = "[" & txs[0].pp
      for n in 1 ..< txs.len:
        rc &= ";" & txs[n].pp
      rc &= "]"
    rc
  txt.multiReplace([
    (",", &",\n   {pfx}"),
    (";", &",\n  {pfx}")])

proc pp*(txs: openArray[Transaction]; pfxLen: int): string =
  txs.pp(" ".repeat(pfxLen))

proc pp*(w: TxTabsItemsCount): string =
  &"{w.pending}/{w.staged}/{w.packed}:{w.total}/{w.disposed}"

# ------------------------------------------------------------------------------
# Public functions, other
# ------------------------------------------------------------------------------

proc toHex*(acc: Address): string =
  acc.toHex

proc say*(noisy = false; pfx = "***"; args: varargs[string, `$`]) =
  if noisy:
    if args.len == 0:
      echo "*** ", pfx
    elif 0 < pfx.len and pfx[^1] != ' ':
      echo pfx, " ", args.toSeq.join
    else:
      echo pfx, args.toSeq.join

proc setTraceLevel* =
  discard
  when defined(chronicles_runtime_filtering) and loggingEnabled:
    setLogLevel(LogLevel.TRACE)

proc setErrorLevel* =
  discard
  when defined(chronicles_runtime_filtering) and loggingEnabled:
    setLogLevel(LogLevel.ERROR)

proc findFilePath*(file: string;
                   baseDir, repoDir: openArray[string]): Result[string,void] =
  for dir in baseDir:
    for repo in repoDir:
      let path = dir / repo / file
      if path.fileExists:
        return ok(path)
  err()

# ------------------------------------------------------------------------------
# End
# ------------------------------------------------------------------------------
