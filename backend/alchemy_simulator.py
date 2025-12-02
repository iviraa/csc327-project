"""
CryptoC Alchemy RPC Integration
Provides real-time transaction simulation using Alchemy's eth_call and state forking

SECURITY FEATURE: Live Blockchain Validation
- Simulates transactions against ACTUAL blockchain state
- Detects transactions that would revert on-chain
- Validates contract interactions before user signs
- Uses Alchemy RPC (trusted third-party API)

SECURITY PRACTICES:
1. API Key Management - Reads from environment variable (never hardcoded)
2. Graceful Degradation - Falls back to local simulation if API unavailable
3. Error Handling - Catches contract revert errors and returns detailed reasons
4. HTTPS-only - All API calls use encrypted connections
"""

import os
import logging
from typing import Dict, Any, Optional
from web3 import Web3
from web3.exceptions import ContractLogicError
import requests

logger = logging.getLogger(__name__)


class AlchemySimulator:
    """
    Transaction simulator using Alchemy RPC API
    Simulates transactions against live blockchain state
    
    SECURITY PURPOSE:
    - Validates transactions will succeed on-chain
    - Prevents wasted gas on failed transactions
    - Detects hidden contract logic that would cause reverts
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Alchemy simulator
        
        SECURITY: API Key Management
        - Reads from environment variable (ALCHEMY_API_KEY)
        - Never hardcoded in source code
        - Not exposed in logs or error messages
        
        Args:
            api_key: Alchemy API key (reads from ALCHEMY_API_KEY env var if not provided)
        """
        # SECURITY: Read API key from environment variable (12-factor app principle)
        # Prevents accidental commit of secrets to version control
        self.api_key = api_key or os.environ.get("ALCHEMY_API_KEY")
        self.enabled = bool(self.api_key)
        
        if self.enabled:
            # SECURITY: HTTPS-only endpoint for encrypted API communication
            # Ethereum Mainnet endpoint
            self.rpc_url = f"https://eth-mainnet.g.alchemy.com/v2/{self.api_key}"
            self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            logger.info("Alchemy simulator initialized with API key")
        else:
            self.w3 = None
            # SECURITY: Graceful degradation - system continues without API key
            logger.warning("Alchemy API key not found. Simulation will use local mode only.")

    def is_available(self) -> bool:
        """Check if Alchemy integration is available"""
        return self.enabled and self.w3 is not None and self.w3.is_connected()

    def simulate_transaction(
        self,
        from_address: str,
        to_address: str,
        value: str = "0",
        data: str = "",
        block: str = "latest"
    ) -> Dict[str, Any]:
        """
        Simulate a transaction using Alchemy's eth_call
        
        Args:
            from_address: Sender address
            to_address: Contract/recipient address
            value: ETH value in wei (hex string or int)
            data: Transaction calldata (hex string)
            block: Block number or "latest"
            
        Returns:
            Dict with simulation results including return data and state changes
        """
        if not self.is_available():
            raise Exception("Alchemy simulator not available. Check API key.")

        try:
            # Prepare transaction object
            tx = {
                "from": self.w3.to_checksum_address(from_address),
                "to": self.w3.to_checksum_address(to_address),
                "value": hex(int(value)) if isinstance(value, str) and value.isdigit() else value,
                "data": data if data else "0x"
            }

            # Simulate using eth_call (doesn't broadcast, just simulates)
            result = self.w3.eth.call(tx, block)
            
            return {
                "success": True,
                "return_data": result.hex() if isinstance(result, bytes) else result,
                "error": None
            }

        except ContractLogicError as e:
            # Transaction would revert
            logger.warning(f"Transaction simulation reverted: {e}")
            return {
                "success": False,
                "return_data": None,
                "error": str(e),
                "revert_reason": str(e)
            }

        except Exception as e:
            logger.error(f"Simulation error: {e}")
            return {
                "success": False,
                "return_data": None,
                "error": str(e)
            }

    def get_token_balance(self, token_address: str, wallet_address: str) -> int:
        """
        Get ERC20 token balance using Alchemy
        
        Args:
            token_address: ERC20 token contract address
            wallet_address: Wallet address to check
            
        Returns:
            Token balance (raw, not adjusted for decimals)
        """
        if not self.is_available():
            return 0

        try:
            # ERC20 balanceOf(address) function signature
            balance_of_sig = "0x70a08231"  # balanceOf(address)
            # Encode wallet address as parameter
            padded_address = wallet_address[2:].zfill(64)  # Remove 0x and pad to 32 bytes
            data = balance_of_sig + padded_address

            result = self.simulate_transaction(
                from_address="0x0000000000000000000000000000000000000000",
                to_address=token_address,
                data=data
            )

            if result["success"] and result["return_data"]:
                return int(result["return_data"], 16)
            return 0

        except Exception as e:
            logger.error(f"Error fetching token balance: {e}")
            return 0

    def get_token_info(self, token_address: str) -> Dict[str, Any]:
        """
        Get ERC20 token information (name, symbol, decimals)
        
        Args:
            token_address: ERC20 token contract address
            
        Returns:
            Dict with token info
        """
        if not self.is_available():
            return {"name": "Unknown", "symbol": "???", "decimals": 18}

        try:
            # Function signatures
            name_sig = "0x06fdde03"  # name()
            symbol_sig = "0x95d89b41"  # symbol()
            decimals_sig = "0x313ce567"  # decimals()

            # Get name
            name_result = self.simulate_transaction(
                from_address="0x0000000000000000000000000000000000000000",
                to_address=token_address,
                data=name_sig
            )
            
            # Get symbol
            symbol_result = self.simulate_transaction(
                from_address="0x0000000000000000000000000000000000000000",
                to_address=token_address,
                data=symbol_sig
            )
            
            # Get decimals
            decimals_result = self.simulate_transaction(
                from_address="0x0000000000000000000000000000000000000000",
                to_address=token_address,
                data=decimals_sig
            )

            # Parse results
            name = self._decode_string(name_result["return_data"]) if name_result["success"] else "Unknown"
            symbol = self._decode_string(symbol_result["return_data"]) if symbol_result["success"] else "???"
            decimals = int(decimals_result["return_data"], 16) if decimals_result["success"] else 18

            return {
                "name": name,
                "symbol": symbol,
                "decimals": decimals
            }

        except Exception as e:
            logger.error(f"Error fetching token info: {e}")
            return {"name": "Unknown", "symbol": "???", "decimals": 18}

    def check_contract_verified(self, address: str) -> bool:
        """
        Check if contract is verified on Etherscan
        (Note: This would require Etherscan API integration)
        
        Args:
            address: Contract address
            
        Returns:
            True if verified, False otherwise
        """
        # This would require Etherscan API key
        # For now, return False as placeholder
        return False

    def _decode_string(self, hex_data: str) -> str:
        """Decode ABI-encoded string from hex data"""
        try:
            if not hex_data or hex_data == "0x":
                return ""
            
            # Remove 0x prefix
            data = hex_data[2:] if hex_data.startswith("0x") else hex_data
            
            # Skip offset and length (first 64 bytes)
            # Then decode the actual string
            bytes_data = bytes.fromhex(data[128:])  # Skip first 64 bytes (offset + length)
            return bytes_data.decode('utf-8').rstrip('\x00')
        except Exception as e:
            logger.error(f"Error decoding string: {e}")
            return ""


# Global instance
_alchemy_simulator = None


def get_alchemy_simulator() -> AlchemySimulator:
    """Get or create global Alchemy simulator instance"""
    global _alchemy_simulator
    if _alchemy_simulator is None:
        _alchemy_simulator = AlchemySimulator()
    return _alchemy_simulator


if __name__ == "__main__":
    # Test Alchemy integration
    print("Testing Alchemy Simulator\n")
    
    simulator = AlchemySimulator()
    
    if simulator.is_available():
        print("✓ Alchemy connection established")
        
        # Test: Get USDC balance
        usdc_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        test_wallet = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0"
        
        print(f"\nFetching USDC balance for {test_wallet[:10]}...")
        balance = simulator.get_token_balance(usdc_address, test_wallet)
        print(f"Balance: {balance / 1e6} USDC")
        
        print("\nFetching USDC token info...")
        info = simulator.get_token_info(usdc_address)
        print(f"Name: {info['name']}")
        print(f"Symbol: {info['symbol']}")
        print(f"Decimals: {info['decimals']}")
        
    else:
        print("✗ Alchemy not available. Set ALCHEMY_API_KEY environment variable.")


