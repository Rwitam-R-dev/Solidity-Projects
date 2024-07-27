// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AccessControl {
    mapping(bytes32 => mapping(address => bool)) private _roles;

    modifier onlyRole(bytes32 role) {
        require(
            hasRole(role, msg.sender),
            "AccessControl: sender must have the specified role"
        );
        _;
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }

    function grantRole(bytes32 role, address account) public onlyRole(role) {
        _roles[role][account] = true;
    }

    function revokeRole(bytes32 role, address account) public onlyRole(role) {
        _roles[role][account] = false;
    }

    function renounceRole(bytes32 role) public {
        _roles[role][msg.sender] = false;
    }
}
