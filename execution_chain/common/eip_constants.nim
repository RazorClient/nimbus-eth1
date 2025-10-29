import
  eth/common/[hashes]

const
  # EIP-7708: MAGIC topic (placeholder, configurable later)
  EIP7708Magic*: Hash32 = hash32"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

  # EIP-7799: Event topics

  # PriorityRewards(address,uint256)
  EIP7799PriorityRewardsTopic*: Hash32 =
    hash32"0x5dfe9c0fd3043bb299f97cfece428f0396cf8b7890c525756e4ea5c0ff7d61b2"

  # Withdrawal(address,uint256)
  EIP7799WithdrawalTopic*: Hash32 =
    hash32"0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65"

  # Genesis(address,uint256)
  EIP7799GenesisTopic*: Hash32 =
    hash32"0xba2f6409ffd24dd4df8e06be958ed8c1706b128913be6e417989c74969b0b55a"
