import
  eth/common/[addresses, base]

export addresses, base

type
  SszReceiptContext* = object
    sender*: Address
    txGasUsed*: uint64 # Gas used by THIS transaction only (not cumulative)
    contractAddress*: Address
    authorities*: seq[Address]
