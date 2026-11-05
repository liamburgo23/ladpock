pragma solidity 0.8.28;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract Vault is Ownable, ReentrancyGuard {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "failed");
    }

    function mint(address to, uint256 amount) external onlyOwner {
        balances[to] += amount;
    }

    function pause() external {
        require(msg.sender == owner(), "not owner");
    }

    function name() external pure returns (string memory) {
        return "vault";
    }
}
