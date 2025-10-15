import
  eth/common/eth_types

# Keep this file in common to make sure there is no circular dependency issues
type
  ReceiptContext* = object
    sender*: Address
    txGasUsed*: uint64 # Gas used by THIS transaction only (not cumulative)
    contractAddress*: Address
    authorities*: seq[Address]
    isCreate*: bool  #  determines CreateReceipt vs BasicReceipt
