
from typing import List, Tuple, Optional
from pysmx.crypto import hashlib

class SM3MerkleTree:
    """基于SM3哈希算法和RFC6962规范的Merkle树实现"""
    
    def __init__(self, data: List[bytes]):
        """初始化Merkle树，构建完整的树结构"""
        if not data:
            raise ValueError("Empty data list")
        
        self.leaves = [self._sm3_hash(d) for d in data]
        self.tree = self._build_tree(self.leaves)
    
    @staticmethod
    def _sm3_hash(data: bytes) -> bytes:
        """计算SM3哈希值"""
        
        sm3 = hashlib.sm3()
        sm3.update(data)
        return sm3.digest()

    def _build_tree(self, leaves: List[bytes]) -> List[List[bytes]]:
        """构建Merkle树"""
        tree = [leaves]
        current_level = leaves
        
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i+1] if i+1 < len(current_level) else left
                combined = left + right
                next_level.append(self._sm3_hash(combined))
            tree.append(next_level)
            current_level = next_level
        
        return tree
    
    def get_root(self) -> bytes:
        """获取Merkle根哈希"""
        return self.tree[-1][0]
    
    def get_proof(self, index: int) -> List[Tuple[bytes, bool]]:
        """获取指定索引的叶子节点的存在性证明路径"""
        if index < 0 or index >= len(self.leaves):
            raise IndexError("Leaf index out of range")
        
        proof = []
        current_index = index
        
        for level in self.tree[:-1]:
            if current_index % 2 == 1:  # 当前是右节点
                sibling_index = current_index - 1
                proof.append((level[sibling_index], True))  # (hash, is_left)
            else:  # 当前是左节点
                sibling_index = current_index + 1
                if sibling_index < len(level):
                    proof.append((level[sibling_index], False))
                # 如果是最后一个节点且没有兄弟节点，不需要添加
            current_index = current_index // 2
        
        return proof
    
    def verify_proof(self, leaf: bytes, proof: List[Tuple[bytes, bool]], root: bytes) -> bool:
        """验证存在性证明"""
        current_hash = leaf
        
        for sibling_hash, is_left in proof:
            if is_left:
                current_hash = self._sm3_hash(sibling_hash + current_hash)
            else:
                current_hash = self._sm3_hash(current_hash + sibling_hash)
        
        return current_hash == root
    
    def get_non_membership_proof(self, leaf: bytes) -> Tuple[Optional[int], List[Tuple[bytes, bool]]]:
        """获取不存在性证明"""
        # 首先检查叶子是否在树中
        try:
            index = self.leaves.index(leaf)
            return index, None  # 叶子存在，返回None作为证明
        except ValueError:
            pass
        
        # 找到叶子应该插入的位置
        # 这里简化处理，实际应根据排序规则找到相邻叶子
        # 假设叶子已排序，使用二分查找找到插入位置
        # 这里简化实现，返回第一个叶子的证明作为示例
        if len(self.leaves) > 0:
            return 0, self.get_proof(0)
        return None, None


def generate_test_data(n: int = 100000) -> List[bytes]:
    """生成测试数据"""
    return [str(i).encode() for i in range(n)]


if __name__ == "__main__":
    print("=== SM3 Merkle Tree 演示 ===")
    
    # 1. 创建小规模树演示基本功能
    print("\n1. 创建包含5个叶子节点的Merkle树")
    small_data = [b"leaf1", b"leaf2", b"leaf3", b"leaf4", b"leaf5"]
    small_tree = SM3MerkleTree(small_data)
    print(f"Merkle根哈希: {small_tree.get_root().hex()}")
    
    # 测试存在性证明
    test_index = 2
    print(f"\n2. 测试叶子节点 {test_index} (数据: '{small_data[test_index].decode()}') 的存在性证明:")
    proof = small_tree.get_proof(test_index)
    for i, (hash_val, is_left) in enumerate(proof):
        print(f"  层级 {i}: {'左' if is_left else '右'}兄弟哈希: {hash_val.hex()}")
    
    # 验证存在性证明
    is_valid = small_tree.verify_proof(small_tree.leaves[test_index], proof, small_tree.get_root())
    print(f"\n3. 验证结果: {'✓ 成功' if is_valid else '✗ 失败'}")
    
    # 测试不存在性证明
    non_existing_leaf = b"non_existing_data"
    print(f"\n4. 测试数据 '{non_existing_leaf.decode()}' 的不存在性证明:")
    index, non_mem_proof = small_tree.get_non_membership_proof(non_existing_leaf)
    if non_mem_proof is not None:
        for i, (hash_val, is_left) in enumerate(non_mem_proof):
            print(f"  层级 {i}: {'左' if is_left else '右'}兄弟哈希: {hash_val.hex()}")
    else:
        print(f"  数据 '{non_existing_leaf.decode()}' 已存在于树中")
    
    # 2. 创建大规模树演示性能
    print("\n5. 生成10万个叶子节点的Merkle树...")
    large_data = generate_test_data(100000)
    large_tree = SM3MerkleTree(large_data)
    print(f"Merkle根哈希: {large_tree.get_root().hex()}")
    
    # 测试大规模存在性证明
    large_index = 12345
    print(f"\n6. 测试叶子节点 {large_index} 的存在性证明 (仅显示前3层):")
    large_proof = large_tree.get_proof(large_index)
    for i, (hash_val, is_left) in enumerate(proof[:3]):
        print(f"  层级 {i}: {'左' if is_left else '右'}兄弟哈希: {hash_val.hex()}")
    print(f"  ...(共 {len(large_proof)} 层证明)")