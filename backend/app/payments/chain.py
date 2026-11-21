"""CashAddr validation and read-only Bitcoin Cash Node RPC."""

import hashlib
import logging
import re
import time
from decimal import Decimal, InvalidOperation
from typing import Any

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
PREFIXES = {
    "mainnet": "bitcoincash",
    "testnet": "bchtest",
    "chipnet": "bchtest",
    "regtest": "bchreg",
}


def _polymod(values: list[int]) -> int:
    c = 1
    for value in values:
        c0 = c >> 35
        c = ((c & 0x07FFFFFFFF) << 5) ^ value
        for bit, generator in enumerate(
            (0x98F2BC8E61, 0x79B76D99E2, 0xF33E5FB3C4, 0xAE2EABE2A8, 0x1E4F43E470)
        ):
            if (c0 >> bit) & 1:
                c ^= generator
    return c ^ 1


def normalize_address(value: str, network: str) -> str:
    prefix = PREFIXES[network]
    if value.startswith(("1", "3")):
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        try:
            number = 0
            for char in value:
                number = number * 58 + alphabet.index(char)
            raw = b"\x00" * (len(value) - len(value.lstrip("1"))) + number.to_bytes(
                (number.bit_length() + 7) // 8, "big"
            )
        except ValueError as exc:
            raise ValueError("Invalid legacy BCH address") from exc
        if (
            network != "mainnet"
            or len(raw) != 25
            or raw[0] not in (0, 5)
            or hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4]
            != raw[-4:]
        ):
            raise ValueError("Invalid legacy BCH checksum or network")
        acc = bits = 0
        digits = []
        for byte in bytes([0 if raw[0] == 0 else 8]) + raw[1:21]:
            acc = (acc << 8) | byte
            bits += 8
            while bits >= 5:
                bits -= 5
                digits.append((acc >> bits) & 31)
        if bits:
            digits.append((acc << (5 - bits)) & 31)
        checksum = _polymod([ord(c) & 31 for c in prefix] + [0] + digits + [0] * 8)
        digits.extend((checksum >> (5 * (7 - i))) & 31 for i in range(8))
        value = f"{prefix}:{''.join(ALPHABET[digit] for digit in digits)}"
    if value.lower() != value and value.upper() != value:
        raise ValueError("Mixed case CashAddr is invalid")
    value = value.lower()
    if ":" not in value:
        value = f"{prefix}:{value}"
    parts = value.split(":")
    if len(parts) != 2 or parts[0] != prefix or len(parts[1]) < 8:
        raise ValueError("CashAddr network does not match")
    try:
        data = [ALPHABET.index(char) for char in parts[1]]
    except ValueError as exc:
        raise ValueError("Invalid CashAddr characters") from exc
    if _polymod([ord(c) & 31 for c in prefix] + [0] + data) != 0:
        raise ValueError("Invalid CashAddr checksum")
    payload = data[:-8]
    acc = bits = 0
    decoded = bytearray()
    for digit in payload:
        acc = (acc << 5) | digit
        bits += 5
        if bits >= 8:
            bits -= 8
            decoded.append((acc >> bits) & 255)
    if not decoded or bits >= 5 or ((acc << (8 - bits)) & 255):
        raise ValueError("Invalid CashAddr padding")
    version = decoded[0]
    hash_sizes = (20, 24, 28, 32, 40, 48, 56, 64)
    if (
        version & 128
        or (version >> 3) not in (0, 1, 2, 3)
        or len(decoded) - 1 != hash_sizes[version & 7]
    ):
        raise ValueError("Invalid CashAddr version")
    address_type = (version >> 3) & 1
    if (address_type == 0 and len(decoded) != 21) or (
        address_type == 1 and len(decoded) not in (21, 33)
    ):
        raise ValueError("Unsupported BCH locking script size")
    if version >> 3 in (2, 3):
        # CashTokens-aware aliases lock to the same script. Canonicalize them so
        # an alias cannot bypass the permanent merchant association.
        decoded[0] &= 15
        acc = bits = 0
        digits = []
        for byte in decoded:
            acc = (acc << 8) | byte
            bits += 8
            while bits >= 5:
                bits -= 5
                digits.append((acc >> bits) & 31)
        if bits:
            digits.append((acc << (5 - bits)) & 31)
        checksum = _polymod([ord(c) & 31 for c in prefix] + [0] + digits + [0] * 8)
        digits.extend((checksum >> (5 * (7 - i))) & 31 for i in range(8))
        return f"{prefix}:{''.join(ALPHABET[digit] for digit in digits)}"
    return value


def address_script_hex(value: str, network: str) -> str:
    """Standard P2PKH/P2SH locking script for a checked CashAddr."""
    normalized = normalize_address(value, network)
    payload = [ALPHABET.index(char) for char in normalized.split(":", 1)[1]][:-8]
    acc = bits = 0
    decoded = bytearray()
    for digit in payload:
        acc = (acc << 5) | digit
        bits += 5
        if bits >= 8:
            bits -= 8
            decoded.append((acc >> bits) & 255)
    version, hash_bytes = decoded[0], bytes(decoded[1:])
    push = f"{len(hash_bytes):02x}{hash_bytes.hex()}"
    if version >> 3 == 0:
        return f"76a9{push}88ac"
    return f"{'aa' if len(hash_bytes) == 32 else 'a9'}{push}87"


def bch_to_sats(value: str | Decimal) -> int:
    try:
        amount = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError("Invalid BCH amount") from exc
    sats = amount * 100_000_000
    if (
        not amount.is_finite()
        or amount <= 0
        or sats != sats.to_integral_value()
        or sats > 2_100_000_000_000_000
    ):
        raise ValueError(
            "BCH amount must be positive with at most eight decimal places"
        )
    return int(sats)


def sats_to_bch(sats: int) -> str:
    return format(Decimal(sats) / Decimal(100_000_000), "f")


class ProviderError(Exception):
    pass


class TransactionNotFound(ProviderError):
    pass


class BCHNodeProvider:
    """Stateless NOWNodes adapter; create a fresh instance per scan cycle."""

    def __init__(
        self,
        url: str | None = None,
        api_key: str | None = None,
        blockbook_url: str | None = None,
    ):
        self.url = url or settings.NOWNODES_BCH_RPC_URL
        self.api_key = api_key if api_key is not None else settings.BCH_API
        self.blockbook_url = (
            blockbook_url or settings.NOWNODES_BCH_BLOCKBOOK_URL
        ).rstrip("/")
        self._transactions: dict[tuple[str, str], dict[str, Any]] = {}

    @staticmethod
    def _diagnose(operation: str, method: str, status: int, code: Any = None) -> None:
        # Only numeric RPC codes are safe; never echo upstream messages/bodies.
        code = code if type(code) is int else None
        logger.log(
            logging.WARNING if status >= 400 or code is not None else logging.INFO,
            "BCH provider operation=%s method=%s http_status=%s error_code=%s",
            operation,
            method,
            status,
            code,
        )

    def _call(self, method: str, params: list[Any] | None = None) -> Any:
        if not self.api_key:
            raise ProviderError("BCH_API is not configured")
        for attempt in range(3):
            try:
                with httpx.Client(
                    timeout=httpx.Timeout(
                        120 if method == "scantxoutset" else 10, connect=5
                    )
                ) as client:
                    response = client.post(
                        self.url,
                        headers={
                            "api-key": self.api_key,
                            "Content-Type": "application/json",
                        },
                        json={
                            "jsonrpc": "1.0",
                            "id": "scan" if method == "scantxoutset" else "proofpay",
                            "method": method,
                            "params": params or [],
                        },
                    )
                    self._diagnose("rpc", method, response.status_code)
                    if response.status_code == 429:
                        logger.warning(
                            "BCH RPC rate limited",
                            extra={"rpc_method": method, "attempt": attempt + 1},
                        )
                        if attempt < 2:
                            time.sleep(0.5 * 2**attempt)
                            continue
                        raise ProviderError(
                            "BCH provider rate limited; retry next cycle"
                        )
                    data = response.json(parse_float=Decimal)
                    if not isinstance(data, dict):
                        raise ValueError("Invalid RPC response")
                    error = data.get("error")
                    if error is not None:
                        if not isinstance(error, dict):
                            raise ValueError("Invalid RPC error")
                        code = error.get("code")
                        self._diagnose("rpc", method, response.status_code, code)
                        if method == "scantxoutset" and code == -8:
                            logger.warning(
                                "BCH scan busy",
                                extra={"rpc_method": method, "attempt": attempt + 1},
                            )
                            if attempt < 2:
                                time.sleep(0.5 * 2**attempt)
                                continue
                            raise ProviderError("BCH scan busy; retry next cycle")
                        if method == "getrawtransaction" and code == -5:
                            raise TransactionNotFound(
                                "Transaction not found by BCH node"
                            )
                        logger.warning(
                            "BCH RPC failed",
                            extra={
                                "rpc_method": method,
                                "rpc_code": code if type(code) is int else None,
                            },
                        )
                        safe_code = code if type(code) is int else None
                        raise ProviderError(
                            f"BCH RPC {method} failed (code {safe_code})"
                        )
                    response.raise_for_status()
                    if "result" not in data:
                        raise ValueError("Missing RPC result")
                    return data["result"]
            except (httpx.HTTPError, ValueError) as exc:
                raise ProviderError(
                    "BCH provider unavailable or returned invalid data"
                ) from exc
        raise ProviderError("BCH provider unavailable")

    def check_network(self, network: str) -> None:
        info = self._call("getblockchaininfo")
        if not isinstance(info, dict):
            raise ProviderError("Invalid chain information")
        chain = info.get("chain")
        expected = {
            "mainnet": "main",
            "testnet": "test",
            "chipnet": "chip",
            "regtest": "regtest",
        }[network]
        if chain != expected:
            raise ProviderError("BCH provider network mismatch")
        if info.get("initialblockdownload") is True:
            raise ProviderError("BCH node is still syncing")

    def watch_address(self, address: str, network: str) -> None:
        # Issuance interface only: shared nodes need no wallet or address import.
        normalize_address(address, network)
        self.check_network(network)

    def _address_page(self, address: str, page: int) -> dict[str, Any]:
        if not self.api_key:
            raise ProviderError("BCH_API is not configured")
        for attempt in range(3):
            try:
                with httpx.Client(timeout=httpx.Timeout(30, connect=5)) as client:
                    response = client.get(
                        f"{self.blockbook_url}/api/v2/address/{address}",
                        headers={"api-key": self.api_key},
                        params={"details": "txids", "page": page, "pageSize": 1000},
                    )
                self._diagnose("address_history", "GET", response.status_code)
                if response.status_code == 429:
                    if attempt < 2:
                        time.sleep(0.5 * 2**attempt)
                        continue
                    raise ProviderError(
                        "BCH address history rate limited; retry next cycle"
                    )
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict) or data.get("error") is not None:
                    raise ValueError("Invalid address history response")
                return data
            except (httpx.HTTPError, ValueError) as exc:
                # Do not propagate URLs, provider messages, or response bodies.
                logger.warning(
                    "BCH provider operation=address_history method=GET failed type=%s",
                    type(exc).__name__,
                )
                raise ProviderError(
                    "BCH address history unavailable or invalid"
                ) from exc
        raise ProviderError("BCH address history unavailable")

    def incoming(self, address: str, network: str) -> list[str]:
        address = normalize_address(address, network)
        self.check_network(network)
        self._transactions.clear()
        txids: set[str] = set()
        page = 1
        while True:
            data = self._address_page(address, page)
            pages, current, rows = (
                data.get("totalPages"),
                data.get("page"),
                data.get("txids", []),
            )
            if (
                type(pages) is not int
                or pages < 0
                or type(current) is not int
                or current != page
                or not isinstance(rows, list)
                or (pages == 0 and rows)
            ):
                raise ProviderError("Invalid BCH address history pagination")
            for txid in rows:
                if not isinstance(txid, str) or not re.fullmatch(
                    r"[0-9a-fA-F]{64}", txid
                ):
                    raise ProviderError("Invalid BCH address history transaction")
                txids.add(txid.lower())
            if page >= pages:
                break
            page += 1
        # The index includes spent receipts, mempool transactions and outgoing
        # transactions. Only node-verified matching outputs are candidates.
        script = address_script_hex(address, network)
        incoming = []
        for txid in sorted(txids):
            try:
                tx = self.transaction(txid, network)
            except TransactionNotFound:
                # Index lag / dropped mempool transaction: no payment evidence.
                continue
            try:
                if any(
                    output["scriptPubKey"]["hex"].lower() == script
                    for output in tx["vout"]
                ):
                    incoming.append(txid)
            except (KeyError, TypeError, AttributeError) as exc:
                raise ProviderError("Invalid BCH transaction output") from exc
        return incoming

    def transaction(self, txid: str, network: str) -> dict[str, Any]:
        if (network, txid) in self._transactions:
            return self._transactions[network, txid]
        self.check_network(network)
        tx = self._call("getrawtransaction", [txid, 1])
        if not isinstance(tx, dict):
            raise ProviderError("Invalid transaction result")
        if tx.get("txid", "").lower() != txid.lower() or not isinstance(
            tx.get("vout"), list
        ):
            raise ProviderError("BCH provider returned a different transaction")
        self._transactions[network, txid] = tx
        return tx
