# Nimbus
# Copyright (c) 2021-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at
#     https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at
#     https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed
# except according to those terms.

## Provision of `eth` and `snap` protocol version parameters
##
## `Eth` related parameters:
##   `ethVersions`: seq[int] -- constant list of all available versions
##   `eth`                   -- type symbol of default version
##   `proto_eth`             -- export of default version directives
##
## `Snap` related parameters:
##   `snap`                  -- type symbol of default version
##   `proto_snap`            -- export of default version directives
##   ..aliases..             -- type names, syntactic sugar (see below)
##

import
  ./protocol/eth68 as proto_eth

type eth* = eth68

# ---------------

import
  ./protocol/snap1 as proto_snap

export
  proto_eth,
  proto_snap

type
  snap* = snap1

  SnapAccountRange* = accountRangeObj
    ## Syntactic sugar, type defined in `snap1`

  SnapStorageRanges* = storageRangesObj
    ## Ditto

  SnapByteCodes* = byteCodesObj
    ## Ditto

  SnapTrieNodes* = trieNodesObj
    ## Ditto

# End
