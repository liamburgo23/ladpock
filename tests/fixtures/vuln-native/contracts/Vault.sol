pragma solidity ^0.6.0;

contract Vault {
    mapping(address => uint) public balances;
    address public owner;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }

    function setOwner(address next) public {
        owner = next;
    }

    function mint(address to, uint amount) external {
        balances[to] += amount;
    }

    function isOwner() public view returns (bool) {
        return tx.origin == owner;
    }

    function lottery() public view returns (uint) {
        return uint(keccak256(abi.encodePacked(block.timestamp))) % 10;
    }

    function run(address target, bytes memory data) public {
        target.delegatecall(data);
    }
}
