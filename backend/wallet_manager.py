"""
CryptoC Wallet Manager
Manages wallet balances, transactions, and logs with SQLite database
"""

import sqlite3
from typing import Dict, List

class WalletManager:
    def __init__(self, db_path='wallet.db'):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Initialize the SQLite database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Wallets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS wallets (
                address TEXT PRIMARY KEY,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Balances table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS balances (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                wallet_address TEXT,
                token_symbol TEXT,
                balance REAL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (wallet_address) REFERENCES wallets(address),
                UNIQUE(wallet_address, token_symbol)
            )
        ''')

        # Transactions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                wallet_address TEXT,
                tx_hash TEXT,
                tx_type TEXT,
                from_token TEXT,
                to_token TEXT,
                amount_from REAL,
                amount_to REAL,
                status TEXT,
                risk_level TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (wallet_address) REFERENCES wallets(address)
            )
        ''')

        # Activity logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                wallet_address TEXT,
                action TEXT,
                details TEXT,
                risk_level TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (wallet_address) REFERENCES wallets(address)
            )
        ''')

        # Token approvals table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                wallet_address TEXT,
                token_symbol TEXT,
                spender_address TEXT,
                amount TEXT,
                approved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                revoked BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (wallet_address) REFERENCES wallets(address)
            )
        ''')

        conn.commit()
        conn.close()

    def create_wallet(self, address: str) -> Dict:
        """Create a new wallet with default balances"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('INSERT INTO wallets (address) VALUES (?)', (address,))

            # Set default balances
            cursor.execute('''
                INSERT INTO balances (wallet_address, token_symbol, balance)
                VALUES (?, 'ETH', 5.42), (?, 'USDC', 2480.0)
            ''', (address, address))

            conn.commit()
            return {'success': True, 'address': address}
        except sqlite3.IntegrityError:
            return {'success': False, 'error': 'Wallet already exists'}
        finally:
            conn.close()

    def get_balances(self, address: str) -> Dict[str, float]:
        """Get all token balances for a wallet"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT token_symbol, balance
            FROM balances
            WHERE wallet_address = ?
        ''', (address,))

        balances = {row[0]: row[1] for row in cursor.fetchall()}
        conn.close()

        return balances

    def update_balance(self, address: str, token: str, amount: float) -> bool:
        """Update token balance (can be positive or negative delta)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            UPDATE balances
            SET balance = balance + ?, updated_at = CURRENT_TIMESTAMP
            WHERE wallet_address = ? AND token_symbol = ?
        ''', (amount, address, token))

        success = cursor.rowcount > 0
        conn.commit()
        conn.close()

        return success

    def add_transaction(self, wallet_address: str, tx_data: Dict) -> int:
        """Add a transaction record"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO transactions
            (wallet_address, tx_hash, tx_type, from_token, to_token,
             amount_from, amount_to, status, risk_level)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            wallet_address,
            tx_data.get('tx_hash', 'pending'),
            tx_data.get('tx_type', 'SWAP'),
            tx_data.get('from_token'),
            tx_data.get('to_token'),
            tx_data.get('amount_from'),
            tx_data.get('amount_to'),
            tx_data.get('status', 'confirmed'),
            tx_data.get('risk_level', 'safe')
        ))

        tx_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return tx_id

    def get_transactions(self, address: str, limit: int = 50) -> List[Dict]:
        """Get transaction history for a wallet"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, tx_hash, tx_type, from_token, to_token,
                   amount_from, amount_to, status, risk_level, timestamp
            FROM transactions
            WHERE wallet_address = ?
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (address, limit))

        transactions = []
        for row in cursor.fetchall():
            transactions.append({
                'id': row[0],
                'tx_hash': row[1],
                'type': row[2],
                'from': row[3],
                'to': row[4],
                'amountFrom': row[5],
                'amountTo': row[6],
                'status': row[7],
                'riskLevel': row[8],
                'timestamp': row[9]
            })

        conn.close()
        return transactions

    def add_log(self, wallet_address: str, action: str, details: str, risk_level: str = 'safe') -> int:
        """Add an activity log entry"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO activity_logs (wallet_address, action, details, risk_level)
            VALUES (?, ?, ?, ?)
        ''', (wallet_address, action, details, risk_level))

        log_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return log_id

    def get_logs(self, address: str, limit: int = 100) -> List[Dict]:
        """Get activity logs for a wallet"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, action, details, risk_level, timestamp
            FROM activity_logs
            WHERE wallet_address = ?
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (address, limit))

        logs = []
        for row in cursor.fetchall():
            logs.append({
                'id': row[0],
                'action': row[1],
                'details': row[2],
                'riskLevel': row[3],
                'timestamp': row[4]
            })

        conn.close()
        return logs

    def add_approval(self, wallet_address: str, token: str, spender: str, amount: str) -> int:
        """Add a token approval record"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO approvals (wallet_address, token_symbol, spender_address, amount)
            VALUES (?, ?, ?, ?)
        ''', (wallet_address, token, spender, amount))

        approval_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return approval_id

    def get_approvals(self, address: str) -> List[Dict]:
        """Get active approvals for a wallet"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, token_symbol, spender_address, amount, approved_at
            FROM approvals
            WHERE wallet_address = ? AND revoked = FALSE
            ORDER BY approved_at DESC
        ''', (address,))

        approvals = []
        for row in cursor.fetchall():
            approvals.append({
                'id': row[0],
                'token': row[1],
                'spender': row[2],
                'amount': row[3],
                'approvedAt': row[4]
            })

        conn.close()
        return approvals

    def revoke_approval(self, approval_id: int) -> bool:
        """Revoke a token approval"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            UPDATE approvals
            SET revoked = TRUE
            WHERE id = ?
        ''', (approval_id,))

        success = cursor.rowcount > 0
        conn.commit()
        conn.close()

        return success

    def get_wallet_stats(self, address: str) -> Dict:
        """Get wallet statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get total transactions
        cursor.execute('''
            SELECT COUNT(*) FROM transactions WHERE wallet_address = ?
        ''', (address,))
        total_tx = cursor.fetchone()[0]

        # Get threats blocked
        cursor.execute('''
            SELECT COUNT(*) FROM activity_logs
            WHERE wallet_address = ? AND action = 'TRANSACTION_REJECTED'
        ''', (address,))
        threats_blocked = cursor.fetchone()[0]

        # Get balances
        balances = self.get_balances(address)

        # Calculate total value (simplified)
        eth_value = balances.get('ETH', 0) * 2500  # $2500 per ETH
        usdc_value = balances.get('USDC', 0)
        total_value = eth_value + usdc_value

        conn.close()

        return {
            'totalValue': total_value,
            'totalTransactions': total_tx,
            'threatsBlocked': threats_blocked,
            'balances': balances
        }

    def execute_swap(self, address: str, from_token: str, to_token: str,
                     amount_from: float, amount_to: float) -> Dict:
        """Execute a token swap transaction"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Check if wallet has sufficient balance
            cursor.execute('''
                SELECT balance FROM balances
                WHERE wallet_address = ? AND token_symbol = ?
            ''', (address, from_token))

            current_balance = cursor.fetchone()
            if not current_balance or current_balance[0] < amount_from:
                return {'success': False, 'error': 'Insufficient balance'}

            # Deduct from token
            cursor.execute('''
                UPDATE balances
                SET balance = balance - ?, updated_at = CURRENT_TIMESTAMP
                WHERE wallet_address = ? AND token_symbol = ?
            ''', (amount_from, address, from_token))

            # Add to token
            cursor.execute('''
                UPDATE balances
                SET balance = balance + ?, updated_at = CURRENT_TIMESTAMP
                WHERE wallet_address = ? AND token_symbol = ?
            ''', (amount_to, address, to_token))

            # Add transaction record
            cursor.execute('''
                INSERT INTO transactions
                (wallet_address, tx_type, from_token, to_token, amount_from, amount_to, status, risk_level)
                VALUES (?, 'SWAP', ?, ?, ?, ?, 'confirmed', 'safe')
            ''', (address, from_token, to_token, amount_from, amount_to))

            conn.commit()

            # Get updated balances
            new_balances = self.get_balances(address)

            return {
                'success': True,
                'balances': new_balances,
                'tx_id': cursor.lastrowid
            }

        except Exception as e:
            conn.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            conn.close()


if __name__ == '__main__':
    # Test the wallet manager
    wm = WalletManager()

    test_address = '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0'

    # Create wallet
    print('Creating wallet...')
    result = wm.create_wallet(test_address)
    print(result)

    # Get balances
    print('\nGetting balances...')
    balances = wm.get_balances(test_address)
    print(balances)

    # Execute swap
    print('\nExecuting swap...')
    swap_result = wm.execute_swap(test_address, 'ETH', 'USDC', 0.5, 1250)
    print(swap_result)

    # Get stats
    print('\nGetting wallet stats...')
    stats = wm.get_wallet_stats(test_address)
    print(stats)
