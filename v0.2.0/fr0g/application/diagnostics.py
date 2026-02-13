from fr0g import HORIZON_URL, CHUNK_SIZE, MAX_ENTRIES_PER_ACCOUNT
from fr0g.application.tx_utils import retrieve_data, fr0gID2stellar
from collections import deque
import requests

def get_file_count(fr0g_id):
    data = retrieve_data(fr0g_id)
    l = [0]
    for x in data:
        if 'fr0g:f' in x[0]:
            try:
                file_str = x[0].split('fr0g:f')[1].split('c')[0]
                num = int(file_str)
                l.append(num)
            except ValueError:
                pass
    return max(l)
def get_minimum_balance(account_id):
    try:
        resp = requests.get(f"{HORIZON_URL}/accounts/{account_id}", timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return float(data.get("min_balance"))
    except Exception:
        return None

def get_xlm_balance(account_id):
    try:
        resp = requests.get(f"{HORIZON_URL}/accounts/{account_id}", timeout=10)
        resp.raise_for_status()
        data = resp.json()
        for bal in data.get("balances", []):
            if bal.get("asset_type") == "native":
                return float(bal.get("balance"))
        return None
    except Exception:
        return None

def is_horizon_reachable(horizon_url: str, timeout=3) -> bool:
    try:
        resp = requests.get(f"{HORIZON_URL}/", timeout=timeout)
        return resp.status_code == 200
    except Exception:
        return False

def stroops_per_byte() -> Optional[float]:
    BASE_FEE_STROOPS       = 100
    AVG_BASE_FEE_STROOPS   = 2000
    CHUNK_SIZE_BYTES       = 64
    OPS_PER_TX             = 100
    MIN_BALANCE_XLM        = 1.0
    EXTRA_RESERVE_PER_DATA = 0.5
    try:
        url = "https://api.coingecko.com/api/v3/simple/price?ids=stellar&vs_currencies=usd"
        r = requests.get(url, timeout=8)
        r.raise_for_status()
        data = r.json()
        if "stellar" in data and "usd" in data["stellar"]:
            xlm_usd = data["stellar"]["usd"]
        else:
            url_fallback = "https://api.coinpaprika.com/v1/tickers/xlm-stellar"
            r2 = requests.get(url_fallback, timeout=5)
            r2.raise_for_status()
            xlm_usd = r2.json()["quotes"]["USD"]["price"]
        print(f"Detected XLM price: ${xlm_usd:.6f}")
    except Exception as e:
        print(f"Error fetching XLM price: {e}")
        return None
    fee_per_chunk_stroops = AVG_BASE_FEE_STROOPS
    fee_per_tx_stroops = AVG_BASE_FEE_STROOPS * OPS_PER_TX
    chunks_per_tx      = OPS_PER_TX
    fee_per_byte       = fee_per_tx_stroops / (chunks_per_tx * CHUNK_SIZE_BYTES)
    stroops_per_xlm = 10_000_000
    reserve_for_data = 499 * EXTRA_RESERVE_PER_DATA
    total_reserve_xlm = MIN_BALANCE_XLM + reserve_for_data
    bytes_per_account = 499 * CHUNK_SIZE_BYTES
    reserve_stroops_per_byte = (total_reserve_xlm * stroops_per_xlm) / bytes_per_account
    total_stroops_per_byte = fee_per_byte + reserve_stroops_per_byte
    print(f"  → Estimated network fee:       {fee_per_byte:.2f} stroops/byte")
    print(f"  → Amortized reserve:   {reserve_stroops_per_byte:.2f} stroops/byte")
    print(f"  → Estimated total:         {total_stroops_per_byte:.2f} stroops/byte")
    return round(total_stroops_per_byte, 2)


def remaining_space(fr0g_id: str) -> int:
    from collections import deque
    visited = set()
    queue = deque([fr0g_id])
    all_accounts = set()
    remaining_slots_total = 0
    MAX_ENTRIES_PER_ACCOUNT = 500
    CHUNK_SIZE = 64
    MAX_TOTAL_ACCOUNTS = 8001  # 1 + 8000 child

    while queue:
        current = queue.popleft()
        if current in visited:
            continue
        visited.add(current)
        all_accounts.add(current)
        
        data_entries = retrieve_data(current)
        used_slots = 0
        
        # Conta solo le entry che "occupano spazio utile" per upload
        for key, _ in data_entries:
            if key.startswith("fr0g:f") or key.startswith("fr0g:next_f"):
                used_slots += 1
            # Opzionale: ignora anche ":fr0g_id:" se vuoi essere aggressivo
            # elif key == f":{current}:":
            #     pass  # non conta come "usato" per chunk

        remaining_in_this = max(0, MAX_ENTRIES_PER_ACCOUNT - used_slots)
        remaining_slots_total += remaining_in_this
        
        # Coda per next
        for key, value in data_entries:
            if key.startswith("fr0g:next_f"):
                next_id = value
                if next_id.startswith("fr0g") and next_id not in visited:
                    queue.append(next_id)

    total_used_accounts = len(all_accounts)
    remaining_accounts = max(0, MAX_TOTAL_ACCOUNTS - total_used_accounts)
    remaining_bytes = remaining_slots_total * CHUNK_SIZE + remaining_accounts * (MAX_ENTRIES_PER_ACCOUNT * CHUNK_SIZE)
    
    return remaining_bytes