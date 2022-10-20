// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.15;

bytes32 constant transferHash = 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef;
bytes32 constant approvalHash = 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925;
uint256 constant totalSupplySlot = 0x00;
uint256 constant packedNameSlot = 0x01;
uint256 constant packedSymbolSlot = 0x02;

/// @title Yul ERC20 with efficient balance accounting
/// @author Philippe Dumonet <philippe@dumo.net>
/// @dev Ensures balance slots aren't zeroed out when balance becomes 0
contract ZeroERC20 {
    event Transfer(
        address indexed sender,
        address indexed receiver,
        uint256 amount
    );
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 amount
    );

    constructor(
        uint256,
        bytes32,
        bytes32
    ) {
        assembly {
            // copy contructor args into memory
            codecopy(0x00, sub(codesize(), 0x60), 0x60)

            let initialSupply := mload(0x00)
            let packedName := mload(0x20)
            let packedSymbol := mload(0x40)

            function getPackedLen(packed) -> len {
                len := shr(0xf8, packed)
            }

            if or(
                or(iszero(initialSupply), shr(0xff, initialSupply)),
                or(
                    gt(getPackedLen(packedName), 0x1f),
                    gt(getPackedLen(packedSymbol), 0x1f)
                )
            ) {
                revert(0x00, 0x00)
            }

            // emit Transfer event
            log3(0x00, 0x20, transferHash, 0x00, caller())

            // update balance
            mstore(0x00, caller())
            let deployerBalSlot := keccak256(0x00, 0x20)
            sstore(deployerBalSlot, or(shl(1, initialSupply), 1))

            // update total supply
            sstore(totalSupplySlot, initialSupply)

            // store name & symbol
            sstore(packedNameSlot, packedName)
            sstore(packedSymbolSlot, packedSymbol)
        }
    }

    function name() external view returns (string memory) {
        _returnPackedString(packedNameSlot);
    }

    function symbol() external view returns (string memory) {
        _returnPackedString(packedSymbolSlot);
    }

    function _returnPackedString(uint256 _packedSlot) internal view {
        assembly {
            let packedString := sload(_packedSlot)
            mstore(0x00, 0x20)
            mstore(0x3f, packedString)
            return(0x00, 0x60)
        }
    }

    function decimals() external pure returns (uint8) {
        assembly {
            mstore(0x00, 18)
            return(0x00, 0x20)
        }
    }

    function totalSupply() external view returns (uint256) {
        assembly {
            mstore(0x00, sload(0x00))
            return(0x00, 0x20)
        }
    }

    function balanceOf(address) external view returns (uint256) {
        assembly {
            mstore(0x00, calldataload(4))
            let rawBalance := sload(keccak256(0x00, 0x20))
            mstore(0x00, shr(1, rawBalance))
            return(0x00, 0x20)
        }
    }

    function transfer(address, uint256) public returns (bool) {
        assembly {
            let recipient := calldataload(0x04)
            let amount := calldataload(0x24)
            let sAmount := shl(1, amount)

            mstore(0x00, caller())
            let senderBalSlot := keccak256(0x00, 0x20)
            let senderBalance := sload(senderBalSlot)

            if or(iszero(recipient), gt(sAmount, senderBalance)) {
                revert(0x00, 0x00)
            }

            // decrease sender bal
            sstore(senderBalSlot, sub(senderBalance, sAmount))

            // increase recipient balance
            mstore(0x00, recipient)
            let recipientBalSlot := keccak256(0x00, 0x20)
            let recipientBal := sload(recipientBalSlot)
            sstore(recipientBalSlot, or(add(recipientBal, sAmount), 1))

            // log
            mstore(0x00, amount)
            log3(0x00, 0x20, transferHash, caller(), recipient)

            // ret
            mstore(0x00, 0x01)
            return(0x00, 0x20)
        }
    }

    function allowance(address, address) external view returns (uint256) {
        assembly {
            calldatacopy(0x00, 0x04, 0x40)
            let allowanceSlot := keccak256(0x00, 0x40)
            mstore(0x00, shr(1, sload(allowanceSlot)))
            return(0x00, 0x20)
        }
    }

    function approve(address, uint256) public returns (bool) {
        assembly {
            let spender := calldataload(0x04)
            let amount := calldataload(0x24)

            if and(shr(0xff, amount), iszero(eq(amount, not(0)))) {
                revert(0x00, 0x00)
            }

            mstore(0x00, caller())
            mstore(0x20, spender)
            let allowanceSlot := keccak256(0x00, 0x40)

            sstore(allowanceSlot, or(shl(1, amount), 1))

            mstore(0x00, amount)
            log3(0x00, 0x20, approvalHash, caller(), spender)

            mstore(0x00, 0x01)
            return(0x00, 0x20)
        }
    }

    function transferFrom(
        address,
        address,
        uint256
    ) external returns (bool) {
        assembly {
            // load in calldata
            let owner := calldataload(0x04)
            let recipient := calldataload(0x24)
            let amount := calldataload(0x44)
            let sAmount := shl(1, amount)

            // calculate allowance slot and load
            mstore(0x00, owner)
            mstore(0x20, caller())
            let allowanceSlot := keccak256(0x00, 0x40)
            let allowance := sload(allowanceSlot)

            // calculate sender balance slot and load
            let senderBalSlot := keccak256(0x00, 0x20)
            let senderBalance := sload(senderBalSlot)

            // basic checks
            if or(
                or(iszero(recipient), gt(sAmount, allowance)),
                gt(sAmount, senderBalance)
            ) {
                revert(0x00, 0x00)
            }

            // update sender balance
            sstore(senderBalSlot, sub(senderBalance, sAmount))

            // calculate recipient balance slot and update
            mstore(0x00, recipient)
            let recipientBalSlot := keccak256(0x00, 0x20)
            let recipientBalance := sload(recipientBalSlot)
            sstore(recipientBalSlot, or(add(recipientBalance, sAmount), 1))

            // only update allowance if not infinite
            if iszero(eq(allowance, not(0))) {
                // update actual allowance
                let newAllowance := sub(allowance, sAmount)
                sstore(allowanceSlot, newAllowance)

                // emit approval update log
                mstore(0x00, newAllowance)
                log3(0x00, 0x20, approvalHash, owner, caller())
            }

            // emit transfer log
            mstore(0x00, amount)
            log3(0x00, 0x20, transferHash, owner, recipient)

            mstore(0x00, 0x01)
            return(0x00, 0x20)
        }
    }
}
