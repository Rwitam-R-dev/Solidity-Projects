// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Pausable {
    bool private _paused;

    event Paused(address account);
    event Unpaused(address account);

    constructor() {
        _paused = false;
    }

    modifier whenNotPaused() {
        require(!_paused, "Pausable: contract is paused");
        _;
    }

    modifier whenPaused() {
        require(_paused, "Pausable: contract is not paused");
        _;
    }

    function pause() public whenNotPaused {
        _paused = true;
        emit Paused(msg.sender);
    }

    function unpause() public whenPaused {
        _paused = false;
        emit Unpaused(msg.sender);
    }

    function isPaused() public view returns (bool) {
        return _paused;
    }
}
