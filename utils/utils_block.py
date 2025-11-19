import hashlib


def compute_merkle_root(tx_hashes):
    """
    tx_hashes: list of str
    """
    if not tx_hashes:
        return None
    current_level = tx_hashes[:]
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            if i + 1 < len(current_level):
                right = current_level[i + 1]
            else:
                right = left  # 如果奇数个节点，重复最后一个
            combined = left + right
            next_level.append(hashlib.sha256(combined.encode()).hexdigest())
        current_level = next_level
    return current_level[0]
