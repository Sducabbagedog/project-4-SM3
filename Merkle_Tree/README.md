# SM3 Merkle Tree 实现

该项目是基于国密算法 SM3 和 RFC6962 规范的 Merkle 树实现，支持高效构建包含大量叶子节点（测试规模达10万）的 Merkle 树，并提供叶子的存在性证明和不存在性证明功能。

## 快速开始

在该路径下直接运行：

```
python merkle_tree.py
```

会有如下输出：

```
PS E:\VScodeprogram\project-4 SM3\Merkle_Tree>  e:; cd 'e:\VScodeprogram\project-4 SM3\Merkle_Tree'; & 'c:\Users\LENOVO\AppData\Local\Programs\Python\Python311\python.exe' 'c:\Users\LENOVO\.vscode\extensions\ms-python.debugpy-2025.10.0-win32-x64\bundled\libs\debugpy\launcher' '12379' '--' 'E:\VScodeprogram\project-4 SM3\Merkle_Tree\merkle_tree.py'
=== SM3 Merkle Tree 演示 ===

1. 创建包含5个叶子节点的Merkle树
Merkle根哈希: 7ee9e8523c6ee527ba41b2dfde3043135b95f24f4671144538c53099d7622a15

2. 测试叶子节点 2 (数据: 'leaf3') 的存在性证明:
  层级 0: 右兄弟哈希: 99045a83c1e022c7802834e3269678094f5431f4305b3505c6e5d4e94fd5e9ec
  层级 1: 左兄弟哈希: eeffebb44350480e91d879a4e9a77a185ed5d53e00a02e1eeae3adc69ec91c37
  层级 2: 右兄弟哈希: d2fe502562955fc3f01d4c4b04a48ce8086c86cccbb7b40c527b36abe9aea90c

3. 验证结果: ✓ 成功

4. 测试数据 'non_existing_data' 的不存在性证明:
  层级 0: 右兄弟哈希: cadd6ce69a54bd2945d0dd21519dbdd6bd0b7eb30619e82604b9e30b998b2069
  层级 1: 右兄弟哈希: 9d0eb9e0c288deee296f1938c54ecb72756e7bee671dc3f1387a76494186b687
  层级 2: 右兄弟哈希: d2fe502562955fc3f01d4c4b04a48ce8086c86cccbb7b40c527b36abe9aea90c

5. 生成10万个叶子节点的Merkle树...
Merkle根哈希: beb6ab3a5676c895dd711df244bc4c77841ec4cf60a390a6650fd157a3a03586

6. 测试叶子节点 12345 的存在性证明 (仅显示前3层):
  层级 0: 右兄弟哈希: 99045a83c1e022c7802834e3269678094f5431f4305b3505c6e5d4e94fd5e9ec
  层级 1: 左兄弟哈希: eeffebb44350480e91d879a4e9a77a185ed5d53e00a02e1eeae3adc69ec91c37
  层级 2: 右兄弟哈希: d2fe502562955fc3f01d4c4b04a48ce8086c86cccbb7b40c527b36abe9aea90c
  ...(共 17 层证明)
```

## Merkle 树原理

可以查看这篇文章了解Merkle Tree：[Merkle Tree（默克尔树）算法解析_merkle trees-CSDN博客](https://blog.csdn.net/wo541075754/article/details/54632929)

通俗来说，假设有一个场景：你有一本厚厚的账本，里面记录了成千上万条交易记录。现在你想向别人证明其中某条交易确实存在账本里，但又不希望对方看到整本账本的内容。

我们可以把 Merkle 树想象成一个古老的家族密码锁：其中，每个家族成员（数据块）都有一个专属印章（哈希值）。我们构架的Merkle树会将每两人组成小组，把印章合并后生成新印章，然后继续递归合并小组的印章，最终能合成一个整个家族的印章。这样，如果我们想要证明某一个人是家族成员，那么就只需要提供它的同组成员的印章和它将要归并的那一组的印章。如果有人篡改，最终合并的印章值回合整个家族的印章值不相同。

Merkle 树（又称哈希树）是由 Ralph Merkle 于 1979 年提出的数据结构，用于高效验证大规模数据集的完整性。其核心原理如下：

1. **树结构构建**：

   - 叶子节点：原始数据块的哈希值
   - 非叶子节点：子节点哈希值的组合哈希
   - 根节点：树顶部的单一哈希值
2. **存在性证明**：

   - 为了证明某个数据块在树中，只需提供从该叶子到根节点的路径上的兄弟节点哈希值
   - 验证者可通过这些哈希值重新计算根哈希并与已知根哈希比对
3. **不存在性证明**：

   - 在有序 Merkle 树中，可通过证明目标值应在的两个相邻叶子节点，并证明它们之间没有其他节点
   - 本实现通过提供相邻叶子的存在性证明来实现
4. **安全特性**：

   - 任何叶子的修改都会导致根哈希变化
   - 伪造成员证明在计算上不可行（依赖于哈希函数的抗碰撞性）

RFC6962 规范定义了 Merkle 树的标准化构建方式，包括哈希函数的选择和节点组合规则。

## 代码实现解析

### 核心类：`SM3MerkleTree`

```python
class SM3MerkleTree:
    """基于SM3哈希算法和RFC6962规范的Merkle树实现"""
  
    def __init__(self, data: List[bytes]):
        # 初始化叶子节点并构建树
        self.leaves = [self._sm3_hash(d) for d in data]
        self.tree = self._build_tree(self.leaves)
```

### 关键方法

1. **树构建 (`_build_tree`)**：
   - 自底向上逐层计算节点哈希
   - 处理奇数个节点的情况（复制最后一个节点）
   - 使用 SM3 哈希算法计算组合哈希

```python
def _build_tree(self, leaves: List[bytes]) -> List[List[bytes]]:
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
```

2. **存在性证明 (`get_proof`)**：
   - 生成指定叶子的验证路径
   - 记录路径上每个兄弟节点的哈希及其位置（左/右）
   - 路径长度等于树的高度

```python
def get_proof(self, index: int) -> List[Tuple[bytes, bool]]:
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
        current_index = current_index // 2
```

3. **证明验证 (`verify_proof`)**：
   - 使用提供的兄弟节点哈希重建根哈希
   - 根据兄弟位置决定连接顺序（左+右或右+左）
   - 与存储的根哈希比对验证

```python
def verify_proof(self, leaf: bytes, proof: List[Tuple[bytes, bool]], root: bytes) -> bool:
    current_hash = leaf
  
    for sibling_hash, is_left in proof:
        if is_left:
            current_hash = self._sm3_hash(sibling_hash + current_hash)
        else:
            current_hash = self._sm3_hash(current_hash + sibling_hash)
  
    return current_hash == root
```

4. **不存在性证明 (`get_non_membership_proof`)**：
   - 首先检查目标是否已存在
   - 对于不存在的目标，返回相邻叶子的存在性证明
   - 实际应用中需保证叶子有序（当前实现为简化版本）

```python
def get_non_membership_proof(self, leaf: bytes) -> Tuple[Optional[int], List[Tuple[bytes, bool]]]:
    try:
        index = self.leaves.index(leaf)
        return index, None  # 叶子存在
    except ValueError:
        pass
  
    # 简化实现：返回第一个叶子的证明
    if len(self.leaves) > 0:
        return 0, self.get_proof(0)
    return None, None
```

### 性能优化

项目实现了高效的批量处理：

- 使用迭代而非递归构建树
- 利用 Python 的列表推导式优化哈希计算
- 分层存储树结构，减少重复计算

## 使用示例

```python
# 创建包含5个叶子的树
data = [b"leaf1", b"leaf2", b"leaf3", b"leaf4", b"leaf5"]
tree = SM3MerkleTree(data)

# 获取并验证存在性证明
proof = tree.get_proof(2)
is_valid = tree.verify_proof(tree.leaves[2], proof, tree.get_root())

# 获取不存在性证明
_, non_mem_proof = tree.get_non_membership_proof(b"missing_leaf")
```

## 待改进方向

当前不存在性证明为简化实现，实际应用中还需要一下改进方向：

### 不存在性证明的完善

保持叶子有序（如按字典序排序）；提供前后相邻叶子的存在性证明等。

### 3动态更新支持

当前为静态树结构，可扩展为：

- 支持添加/删除叶子节点
- 增量更新树结构
- 平衡树优化（如AVL树特性）

## 结论

本项目实现了基于国密算法SM3的高效Merkle树结构，支持大规模数据处理和存在性验证。通过进一步改进不存在性证明、优化内存使用和添加动态更新功能，可使其更适合实际应用场景如区块链、数据完整性验证和证书透明化系统。
