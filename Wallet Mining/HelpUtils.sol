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
