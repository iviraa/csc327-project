"""
CryptoC Blockchain Transaction Simulator
Simulates Ethereum transactions with real cryptographic operations
Integrates with Alchemy RPC for live blockchain state analysis
"""

import hashlib
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from decimal import Decimal
from eth_abi import decode, encode
from eth_utils import keccak, to_checksum_address, to_wei, from_wei
import re
import logging

logger = logging.getLogger(__name__)


@dataclass
class SimulatedBalance:
    """Represents token/ETH balance"""
    address: str
    balance: str  # in wei for ETH, in smallest unit for tokens
    token_address: Optional[str] = None  # None for ETH, address for ERC20
    token_symbol: Optional[str] = None
    token_decimals: int = 18


@dataclass
class TransactionEffect:
    """Represents the effect of a transaction"""
    from_address: str
    to_address: str
    value: str  # amount transferred in wei
    effect_type: str  # "transfer", "approve", "transferFrom", "mint", "burn"
    token_address: Optional[str] = None
    token_symbol: Optional[str] = None
    approval_amount: Optional[str] = None  # for approve() calls


@dataclass
class SimulationResult:
    """Complete simulation result"""
    success: bool
    effects: List[TransactionEffect]
    gas_used: int
    risk_level: str  # "safe", "warning", "danger"
    risk_score: float  # 0-100
    warnings: List[str]
    balance_changes: Dict[str, List[SimulatedBalance]]
    contract_info: Optional[Dict[str, Any]] = None


class EthereumSimulator:
    """Simulates Ethereum blockchain transactions"""

    # ERC20 function signatures
    TRANSFER_SIG = keccak(text="transfer(address,uint256)")[:4].hex()
    APPROVE_SIG = keccak(text="approve(address,uint256)")[:4].hex()
    TRANSFER_FROM_SIG = keccak(text="transferFrom(address,address,uint256)")[:4].hex()

    # ERC721 (NFT) function signatures
    SAFE_TRANSFER_FROM_SIG = keccak(text="safeTransferFrom(address,address,uint256)")[:4].hex()
    SET_APPROVAL_FOR_ALL_SIG = keccak(text="setApprovalForAll(address,bool)")[:4].hex()

    # Common dangerous patterns
    UNLIMITED_APPROVAL = 2**256 - 1  # type(uint256).max

    def __init__(self, use_alchemy: bool = True):
        """
        Initialize simulator with state storage
        
        Args:
            use_alchemy: If True, will attempt to use Alchemy for real blockchain data
        """
        self.balances: Dict[str, Dict[str, Decimal]] = {}  # address -> {token_address -> balance}
        self.approvals: Dict[str, Dict[str, Decimal]] = {}  # owner -> {spender -> amount}
        self.nft_approvals: Dict[str, Dict[int, str]] = {}  # contract -> {tokenId -> approved_address}
        
        # Try to initialize Alchemy simulator
        self.alchemy = None
        if use_alchemy:
            try:
                from alchemy_simulator import get_alchemy_simulator
                self.alchemy = get_alchemy_simulator()
                if self.alchemy.is_available():
                    logger.info("Alchemy integration enabled for transaction simulation")
                else:
                    logger.info("Alchemy not available, using local simulation only")
            except Exception as e:
                logger.warning(f"Could not initialize Alchemy: {e}")

    def simulate_transaction(
        self,
        from_address: str,
        to_address: str,
        value: str = "0",
        data: str = "",
        gas_limit: int = 21000
    ) -> SimulationResult:
        """
        Simulate an Ethereum transaction and predict its effects

        Args:
            from_address: Sender's address
            to_address: Contract or recipient address
            value: ETH value in wei (as string)
            data: Transaction calldata (hex string)
            gas_limit: Gas limit for transaction

        Returns:
            SimulationResult with predicted effects and risk analysis
        """
        from_address = to_checksum_address(from_address)
        to_address = to_checksum_address(to_address)

        effects = []
        warnings = []
        gas_used = 21000  # Base gas

        # Handle ETH transfer
        if int(value) > 0:
            effects.append(TransactionEffect(
                from_address=from_address,
                to_address=to_address,
                value=value,
                effect_type="transfer",
                token_symbol="ETH"
            ))

        # Try Alchemy simulation first for real-world validation
        if self.alchemy and self.alchemy.is_available() and data:
            try:
                alchemy_result = self.alchemy.simulate_transaction(
                    from_address=from_address,
                    to_address=to_address,
                    value=value,
                    data=data
                )
                
                if not alchemy_result["success"]:
                    warnings.append(f"⚠️ Transaction would REVERT on actual blockchain")
                    if alchemy_result.get("revert_reason"):
                        warnings.append(f"Reason: {alchemy_result['revert_reason']}")
                    
            except Exception as e:
                logger.warning(f"Alchemy simulation failed: {e}")

        # Decode contract call
        if data and len(data) > 10:  # Has function call
            function_sig = data[:10]  # 0x + 8 chars
            calldata = data[10:]

            gas_used += 50000  # Contract interaction gas

            # Decode based on function signature
            if function_sig == f"0x{self.APPROVE_SIG}":
                effect, warning = self._decode_approve(from_address, to_address, calldata)
                if effect:
                    effects.append(effect)
                if warning:
                    warnings.extend(warning)

            elif function_sig == f"0x{self.TRANSFER_SIG}":
                effect = self._decode_transfer(from_address, to_address, calldata)
                if effect:
                    effects.append(effect)

            elif function_sig == f"0x{self.TRANSFER_FROM_SIG}":
                effect = self._decode_transfer_from(to_address, calldata)
                if effect:
                    effects.append(effect)

            elif function_sig == f"0x{self.SET_APPROVAL_FOR_ALL_SIG}":
                effect, warning = self._decode_set_approval_for_all(from_address, to_address, calldata)
                if effect:
                    effects.append(effect)
                if warning:
                    warnings.extend(warning)

            elif function_sig == f"0x{self.SAFE_TRANSFER_FROM_SIG}":
                effect = self._decode_nft_transfer(to_address, calldata)
                if effect:
                    effects.append(effect)
            else:
                warnings.append(f"Unknown function signature: {function_sig}")
                gas_used += 100000  # Unknown function, estimate high gas

        # Calculate risk
        risk_level, risk_score = self._calculate_risk(effects, warnings, to_address)

        # Simulate balance changes
        balance_changes = self._simulate_balance_changes(effects, from_address)

        return SimulationResult(
            success=True,
            effects=effects,
            gas_used=gas_used,
            risk_level=risk_level,
            risk_score=risk_score,
            warnings=warnings,
            balance_changes=balance_changes,
            contract_info=self._get_contract_info(to_address)
        )

    def _decode_approve(
        self,
        from_address: str,
        token_address: str,
        calldata: str
    ) -> Tuple[Optional[TransactionEffect], Optional[List[str]]]:
        """Decode ERC20 approve() function"""
        try:
            # Decode: approve(address spender, uint256 amount)
            params = decode(['address', 'uint256'], bytes.fromhex(calldata))
            spender = to_checksum_address(params[0])
            amount = str(params[1])

            warnings = []

            # Check for unlimited approval (MAJOR RED FLAG)
            if params[1] >= self.UNLIMITED_APPROVAL * 0.9:  # Close to max uint256
                warnings.append("⚠️ UNLIMITED TOKEN APPROVAL DETECTED")
                warnings.append(f"This allows {spender} to spend ALL your tokens forever!")
                warnings.append("This is a common pattern used by token drainer scams")

            effect = TransactionEffect(
                from_address=from_address,
                to_address=spender,
                value="0",
                token_address=token_address,
                token_symbol="UNKNOWN_TOKEN",  # Would need to fetch from contract
                effect_type="approve",
                approval_amount=amount
            )

            return effect, warnings if warnings else None

        except Exception as e:
            print(f"Error decoding approve: {e}")
            return None, [f"Failed to decode approve call: {str(e)}"]

    def _decode_transfer(
        self,
        from_address: str,
        token_address: str,
        calldata: str
    ) -> Optional[TransactionEffect]:
        """Decode ERC20 transfer() function"""
        try:
            # Decode: transfer(address to, uint256 amount)
            params = decode(['address', 'uint256'], bytes.fromhex(calldata))
            to = to_checksum_address(params[0])
            amount = str(params[1])

            return TransactionEffect(
                from_address=from_address,
                to_address=to,
                value=amount,
                token_address=token_address,
                token_symbol="UNKNOWN_TOKEN",
                effect_type="transfer"
            )
        except Exception as e:
            print(f"Error decoding transfer: {e}")
            return None

    def _decode_transfer_from(
        self,
        token_address: str,
        calldata: str
    ) -> Optional[TransactionEffect]:
        """Decode ERC20 transferFrom() function"""
        try:
            # Decode: transferFrom(address from, address to, uint256 amount)
            params = decode(['address', 'address', 'uint256'], bytes.fromhex(calldata))
            from_addr = to_checksum_address(params[0])
            to_addr = to_checksum_address(params[1])
            amount = str(params[2])

            return TransactionEffect(
                from_address=from_addr,
                to_address=to_addr,
                value=amount,
                token_address=token_address,
                token_symbol="UNKNOWN_TOKEN",
                effect_type="transferFrom"
            )
        except Exception as e:
            print(f"Error decoding transferFrom: {e}")
            return None

    def _decode_set_approval_for_all(
        self,
        from_address: str,
        nft_contract: str,
        calldata: str
    ) -> Tuple[Optional[TransactionEffect], Optional[List[str]]]:
        """Decode ERC721 setApprovalForAll() function"""
        try:
            # Decode: setApprovalForAll(address operator, bool approved)
            params = decode(['address', 'bool'], bytes.fromhex(calldata))
            operator = to_checksum_address(params[0])
            approved = params[1]

            warnings = []
            if approved:
                warnings.append("⚠️ NFT APPROVAL FOR ALL DETECTED")
                warnings.append(f"This allows {operator} to transfer ALL your NFTs in this collection!")
                warnings.append("Common in NFT phishing scams - verify the operator address carefully")

            effect = TransactionEffect(
                from_address=from_address,
                to_address=operator,
                value="0",
                token_address=nft_contract,
                token_symbol="NFT",
                effect_type="setApprovalForAll",
                approval_amount="ALL" if approved else "0"
            )

            return effect, warnings if warnings else None

        except Exception as e:
            print(f"Error decoding setApprovalForAll: {e}")
            return None, [f"Failed to decode NFT approval: {str(e)}"]

    def _decode_nft_transfer(
        self,
        nft_contract: str,
        calldata: str
    ) -> Optional[TransactionEffect]:
        """Decode ERC721 safeTransferFrom() function"""
        try:
            # Decode: safeTransferFrom(address from, address to, uint256 tokenId)
            params = decode(['address', 'address', 'uint256'], bytes.fromhex(calldata))
            from_addr = to_checksum_address(params[0])
            to_addr = to_checksum_address(params[1])
            token_id = str(params[2])

            return TransactionEffect(
                from_address=from_addr,
                to_address=to_addr,
                value=token_id,  # Token ID instead of amount for NFTs
                token_address=nft_contract,
                token_symbol="NFT",
                effect_type="nftTransfer"
            )
        except Exception as e:
            print(f"Error decoding NFT transfer: {e}")
            return None

    def _calculate_risk(
        self,
        effects: List[TransactionEffect],
        warnings: List[str],
        to_address: str
    ) -> Tuple[str, float]:
        """
        Calculate risk level based on transaction effects

        Returns:
            (risk_level, risk_score) where:
            - risk_level: "safe", "warning", "danger"
            - risk_score: 0-100 (0 = safe, 100 = extremely dangerous)
        """
        risk_score = 0.0

        # Check for dangerous patterns
        for effect in effects:
            # Unlimited approvals are HIGH RISK
            if effect.effect_type == "approve":
                if effect.approval_amount and int(effect.approval_amount) >= self.UNLIMITED_APPROVAL * 0.9:
                    risk_score += 70
                else:
                    risk_score += 10

            # NFT approval for all is HIGH RISK
            elif effect.effect_type == "setApprovalForAll":
                if effect.approval_amount == "ALL":
                    risk_score += 65

            # Large transfers might be suspicious
            elif effect.effect_type in ["transfer", "transferFrom"]:
                risk_score += 5

        # Each warning adds risk
        risk_score += len(warnings) * 15

        # Check if contract address looks suspicious (not verified, etc.)
        # This would require real contract verification in production

        # Cap at 100
        risk_score = min(100, risk_score)

        # Determine level
        if risk_score >= 60:
            risk_level = "danger"
        elif risk_score >= 30:
            risk_level = "warning"
        else:
            risk_level = "safe"

        return risk_level, risk_score

    def _simulate_balance_changes(
        self,
        effects: List[TransactionEffect],
        user_address: str
    ) -> Dict[str, List[SimulatedBalance]]:
        """Simulate how balances would change after transaction"""
        balance_changes = {
            "before": [],
            "after": []
        }

        # This would query real balances in production
        # For now, return empty to be filled by frontend

        return balance_changes

    def _get_contract_info(self, address: str) -> Dict[str, Any]:
        """Get contract information using Alchemy if available"""
        # Try to get real contract info from Alchemy
        if self.alchemy and self.alchemy.is_available():
            try:
                # Check if it's a token contract
                token_info = self.alchemy.get_token_info(address)
                
                return {
                    "is_contract": True,
                    "verified": self.alchemy.check_contract_verified(address),
                    "name": token_info.get("name", "Unknown Contract"),
                    "symbol": token_info.get("symbol"),
                    "decimals": token_info.get("decimals", 18),
                    "has_audit": False  # Would need separate audit database
                }
            except Exception as e:
                logger.warning(f"Could not fetch contract info: {e}")

        # Fallback to placeholder data
        return {
            "is_contract": True,
            "verified": False,
            "name": "Unknown Contract",
            "has_audit": False
        }


def analyze_transaction_data(tx_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze raw transaction data and return simulation results

    Args:
        tx_data: Dict with keys: from, to, value, data, gasLimit

    Returns:
        Dict with simulation results ready for API response
    """
    simulator = EthereumSimulator()

    result = simulator.simulate_transaction(
        from_address=tx_data.get("from", "0x0000000000000000000000000000000000000000"),
        to_address=tx_data.get("to", "0x0000000000000000000000000000000000000000"),
        value=tx_data.get("value", "0"),
        data=tx_data.get("data", ""),
        gas_limit=tx_data.get("gasLimit", 21000)
    )

    # Convert to JSON-serializable dict
    return {
        "success": result.success,
        "effects": [asdict(effect) for effect in result.effects],
        "gas_used": result.gas_used,
        "risk_level": result.risk_level,
        "risk_score": result.risk_score,
        "warnings": result.warnings,
        "balance_changes": result.balance_changes,
        "contract_info": result.contract_info
    }


if __name__ == "__main__":
    # Test the simulator
    print("Testing Ethereum Transaction Simulator\n")

    # Test 1: Unlimited approval (DANGER)
    print("=" * 60)
    print("TEST 1: Unlimited Token Approval (Common Scam)")
    print("=" * 60)

    # ERC20 approve(address spender, uint256 amount) with max uint256
    spender = "0x1234567890123456789012345678901234567890"
    amount = 2**256 - 1  # Unlimited

    approve_data = "0x" + EthereumSimulator.APPROVE_SIG + \
                   encode(['address', 'uint256'], [spender, amount]).hex()

    tx1 = {
        "from": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
        "to": "0xdAC17F958D2ee523a2206206994597C13D831ec7",  # USDT contract
        "value": "0",
        "data": approve_data,
        "gasLimit": 100000
    }

    result1 = analyze_transaction_data(tx1)
    print(f"Risk Level: {result1['risk_level'].upper()}")
    print(f"Risk Score: {result1['risk_score']}/100")
    print(f"Warnings: {len(result1['warnings'])}")
    for warning in result1['warnings']:
        print(f"  - {warning}")
    print()

    # Test 2: Normal ETH transfer (SAFE)
    print("=" * 60)
    print("TEST 2: Normal ETH Transfer (Safe)")
    print("=" * 60)

    tx2 = {
        "from": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
        "to": "0x1234567890123456789012345678901234567890",
        "value": str(to_wei(0.1, 'ether')),
        "data": "",
        "gasLimit": 21000
    }

    result2 = analyze_transaction_data(tx2)
    print(f"Risk Level: {result2['risk_level'].upper()}")
    print(f"Risk Score: {result2['risk_score']}/100")
    print(f"Effects: {len(result2['effects'])}")
    for effect in result2['effects']:
        print(f"  - {effect['effect_type']}: {from_wei(int(effect['value']), 'ether')} ETH")
    print()
