# payatom_bot/creds.py
"""
Enterprise-grade credential management for PayTrix Bot.

Features:
- AES-256 encryption at rest (optional, backward compatible)
- File permission validation
- Thread-safe credential caching
- Integration with existing logging and error handling
- Audit trail for all credential operations

Security:
- Passwords can be encrypted using Fernet (AES-256)
- Encryption key managed via environment variable
- Strict file permission checks
- PII masking via existing PIIMaskingFilter
- No credentials in exception messages

Usage:
    # Unencrypted CSV (current/legacy)
    creds = load_creds("credentials.csv")
    
    # Encrypted CSV (recommended for production)
    creds = load_creds("credentials.csv.enc", encrypted=True)
    
    # Auto-detect encryption
    creds = load_creds("credentials.csv", auto_detect_encryption=True)
"""
from __future__ import annotations

import csv
import logging
import os
import stat
import threading
from typing import Dict, Optional, Tuple
from pathlib import Path
from datetime import datetime

# Import existing PayTrix infrastructure
from .logging_config import log_audit_event
from .error_handler import ErrorContext, safe_operation

logger = logging.getLogger(__name__)

# Thread-safe cache for credentials
_creds_cache: Dict[str, Tuple[Dict[str, dict], float]] = {}
_cache_lock = threading.Lock()
CACHE_TTL_SECONDS = 300  # 5 minutes


# ============================================================
# Bank Label Mapping
# ============================================================

BANK_LABEL_BY_SUFFIX: Dict[str, str] = {
    "_tmb":     "TMB",
    "_iobcorp": "IOB Corporate",
    "_iob":     "IOB",
    "_kgb":     "KGB",
    "_idbi":    "IDBI",
    "_idfc":    "IDFC",
    "_canara":  "CANARA",
    "_cnrb":    "CANARA",
    "_uco":     "UCO",
    "_ucob":    "UCO",
}


# ============================================================
# Encryption Support (Optional)
# ============================================================

def get_encryption_key() -> Optional[bytes]:
    """
    Retrieve encryption key from environment variable.
    
    Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    
    Returns:
        Encryption key bytes, or None if not configured
    """
    key_str = os.environ.get("CREDENTIALS_ENCRYPTION_KEY", "").strip()
    if not key_str:
        return None
    
    try:
        return key_str.encode('utf-8')
    except Exception as e:
        logger.error("Invalid encryption key format: %s", e)
        return None


def encrypt_credential_field(value: str, key: bytes) -> str:
    """Encrypt credential field using Fernet (AES-256)."""
    try:
        from cryptography.fernet import Fernet
        f = Fernet(key)
        encrypted = f.encrypt(value.encode('utf-8'))
        return encrypted.decode('utf-8')
    except ImportError:
        raise RuntimeError(
            "Encryption requires 'cryptography' package. "
            "Install with: pip install cryptography"
        )
    except Exception as e:
        raise RuntimeError(f"Encryption failed: {e}")


def decrypt_credential_field(encrypted_value: str, key: bytes) -> str:
    """Decrypt credential field using Fernet (AES-256)."""
    try:
        from cryptography.fernet import Fernet
        f = Fernet(key)
        decrypted = f.decrypt(encrypted_value.encode('utf-8'))
        return decrypted.decode('utf-8')
    except ImportError:
        raise RuntimeError(
            "Decryption requires 'cryptography' package. "
            "Install with: pip install cryptography"
        )
    except Exception as e:
        raise RuntimeError(f"Decryption failed: {e}")


# ============================================================
# File Security Validation
# ============================================================

def validate_file_permissions(csv_path: str, strict: bool = False) -> None:
    """
    Validate credentials file has secure permissions.
    
    Recommended: 600 (rw-------) or 400 (r--------)
    
    Args:
        csv_path: Path to credentials file
        strict: If True, raise error on insecure permissions
        
    Raises:
        PermissionError: If strict=True and permissions are insecure
    """
    if not os.path.exists(csv_path):
        return  # File doesn't exist yet
    
    try:
        file_stat = os.stat(csv_path)
        mode = stat.S_IMODE(file_stat.st_mode)
        
        # Check if group or others have any permissions
        group_perms = mode & stat.S_IRWXG
        other_perms = mode & stat.S_IRWXO
        
        if group_perms or other_perms:
            perms_str = oct(mode)
            msg = (
                f"Credentials file has insecure permissions: {perms_str}\n"
                f"File: {csv_path}\n"
                f"Recommended: chmod 600 {csv_path}"
            )
            
            if strict:
                logger.error(msg)
                raise PermissionError(msg)
            else:
                logger.warning(msg)
        else:
            logger.debug("Credentials file permissions OK: %s", oct(mode))
            
    except OSError as e:
        logger.warning("Unable to check file permissions for %s: %s", csv_path, e)


# ============================================================
# Core Functions
# ============================================================

def infer_bank_label_from_alias(alias: str) -> str:
    """
    Infer bank label from alias suffix.
    
    Args:
        alias: Account alias
        
    Returns:
        Bank label string (e.g., "TMB", "IOB Corporate")
    """
    normalized = alias.lower().strip()
    
    # Check predefined mappings
    for suffix, label in BANK_LABEL_BY_SUFFIX.items():
        if normalized.endswith(suffix):
            return label
    
    # Fallback: extract last segment and uppercase
    if "_" in normalized:
        last_segment = normalized.rsplit("_", 1)[-1]
        return last_segment.upper()
    
    return normalized.upper()


def canonical_auth_id(username: str, login_id: str, user_id: str) -> Optional[str]:
    """
    Determine canonical authentication ID from available fields.
    
    Priority: username → login_id → user_id
    
    Args:
        username: Username field
        login_id: Login ID field  
        user_id: User ID field
        
    Returns:
        First non-empty authentication identifier, or None
    """
    for value in (username or "", login_id or "", user_id or ""):
        cleaned = value.strip()
        if cleaned:
            return cleaned
    return None


def validate_credential_dict(cred: dict, alias: str, line_num: int) -> Tuple[bool, Optional[str]]:
    """
    Validate credential dictionary has all required fields.
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not cred.get("auth_id"):
        return False, f"Line {line_num} (alias: {alias}): Missing username/login_id/user_id"
    
    if not cred.get("password"):
        return False, f"Line {line_num} (alias: {alias}): Missing password"
    
    if not cred.get("account_number"):
        return False, f"Line {line_num} (alias: {alias}): Missing account_number"
    
    return True, None


def sanitize_account_number(account_number: str) -> str:
    """
    Sanitize account number (remove separators).
    
    Note: PII masking is handled by existing PIIMaskingFilter in logs.
    """
    return ''.join(c for c in account_number if c.isalnum())


# ============================================================
# Credential Loading
# ============================================================

def load_creds(
    csv_path: str,
    *,
    encrypted: bool = False,
    auto_detect_encryption: bool = False,
    validate_permissions: bool = True,
    use_cache: bool = True,
    strict_permissions: bool = False,
) -> Dict[str, dict]:
    """
    Load credentials from CSV file.
    
    CSV Schema (unencrypted):
        alias,login_id,user_id,username,password,account_number
        
    CSV Schema (encrypted):
        alias,login_id,user_id,username,password_encrypted,account_number
        
    Returns:
        Dictionary mapping alias to credential dict with keys:
        alias, auth_id, password, account_number, bank_label,
        login_id, user_id, username, _loaded_at, _encrypted
        
    Args:
        csv_path: Path to credentials CSV file
        encrypted: If True, expect encrypted passwords
        auto_detect_encryption: Auto-detect encryption from headers
        validate_permissions: Check file has secure permissions
        use_cache: Use cached credentials if available
        strict_permissions: Raise error on insecure permissions
        
    Raises:
        FileNotFoundError: If CSV file doesn't exist
        ValueError: If CSV is malformed or missing columns
        PermissionError: If CSV cannot be read or has insecure permissions
        RuntimeError: If encryption key required but not found
    """
    # Normalize path
    csv_path = os.path.abspath(csv_path)
    
    # Check cache first (thread-safe)
    if use_cache:
        with _cache_lock:
            if csv_path in _creds_cache:
                cached_creds, cache_time = _creds_cache[csv_path]
                age = datetime.now().timestamp() - cache_time
                
                if age < CACHE_TTL_SECONDS:
                    logger.debug(
                        "Using cached credentials from %s (age: %.1fs)",
                        csv_path,
                        age
                    )
                    return cached_creds.copy()
    
    # Use ErrorContext for comprehensive error handling
    with ErrorContext(
        f"loading credentials from {os.path.basename(csv_path)}",
        operation="load_credentials",
        reraise=True
    ):
        # Validate file permissions
        if validate_permissions:
            safe_operation(
                validate_file_permissions,
                csv_path,
                strict_permissions,
                context=f"validate permissions for {csv_path}",
                log_errors=True
            )
        
        # Get encryption key if needed
        encryption_key = None
        if encrypted or auto_detect_encryption:
            encryption_key = get_encryption_key()
            if encrypted and not encryption_key:
                raise RuntimeError(
                    "Encrypted credentials require CREDENTIALS_ENCRYPTION_KEY environment variable. "
                    "Generate with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
                )
        
        logger.info(
            "Loading credentials from: %s (encrypted=%s, auto_detect=%s)",
            csv_path,
            encrypted,
            auto_detect_encryption
        )
        
        try:
            with open(csv_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                
                # Validate headers exist
                if not reader.fieldnames:
                    raise ValueError(
                        f"CSV file '{csv_path}' appears to be empty or malformed. "
                        "Expected columns: alias, login_id, user_id, username, password, account_number"
                    )
                
                # Required columns
                required_base = {"alias", "login_id", "user_id", "username", "account_number"}
                password_fields = {"password", "password_encrypted"}
                
                headers_lower = {h.lower() for h in reader.fieldnames}
                
                # Check for password field
                has_password = any(p in headers_lower for p in password_fields)
                if not has_password:
                    raise ValueError(
                        f"CSV file '{csv_path}' missing password field. "
                        f"Expected one of: {', '.join(password_fields)}"
                    )
                
                # Auto-detect encryption from headers
                is_encrypted = "password_encrypted" in headers_lower
                if auto_detect_encryption:
                    encrypted = is_encrypted
                    if is_encrypted:
                        logger.info("Auto-detected encrypted credentials file")
                        if not encryption_key:
                            raise RuntimeError(
                                "Encrypted credentials detected but CREDENTIALS_ENCRYPTION_KEY not set"
                            )
                
                # Validate required base columns
                missing = required_base - headers_lower
                if missing:
                    raise ValueError(
                        f"CSV file '{csv_path}' missing required columns: {', '.join(sorted(missing))}"
                    )
                
                # Process rows
                out: Dict[str, dict] = {}
                line_num = 1  # Header is line 1
                skipped_count = 0
                skipped_reasons: list[str] = []
                
                for row in reader:
                    line_num += 1
                    alias = (row.get("alias") or "").strip()
                    
                    if not alias:
                        skipped_count += 1
                        skipped_reasons.append(f"Line {line_num}: Empty alias")
                        continue
                    
                    # Extract fields
                    login_id = (row.get("login_id") or "").strip()
                    user_id = (row.get("user_id") or "").strip()
                    username = (row.get("username") or "").strip()
                    account_number = (row.get("account_number") or "").strip()
                    
                    # Get password (encrypted or plaintext)
                    if encrypted:
                        password_encrypted = (row.get("password_encrypted") or row.get("password") or "").strip()
                        if not password_encrypted:
                            skipped_count += 1
                            skipped_reasons.append(f"Line {line_num} (alias: {alias}): Missing password")
                            continue
                        
                        # Decrypt password
                        try:
                            password = decrypt_credential_field(password_encrypted, encryption_key)
                        except Exception as e:
                            skipped_count += 1
                            skipped_reasons.append(
                                f"Line {line_num} (alias: {alias}): Decryption failed"
                            )
                            logger.error(
                                "Failed to decrypt password for alias %s at line %d: %s",
                                alias,
                                line_num,
                                type(e).__name__
                            )
                            continue
                    else:
                        password = (row.get("password") or "").strip()
                    
                    # Determine canonical auth ID
                    auth_id = canonical_auth_id(username, login_id, user_id)
                    
                    # Build credential dict (matches existing format)
                    cred = {
                        "alias": alias,
                        "auth_id": auth_id,
                        "password": password,
                        "account_number": sanitize_account_number(account_number),
                        "bank_label": infer_bank_label_from_alias(alias),
                        "login_id": login_id,
                        "user_id": user_id,
                        "username": username,
                        "_loaded_at": datetime.now(),
                        "_encrypted": encrypted,
                    }
                    
                    # Validate credential
                    is_valid, error_msg = validate_credential_dict(cred, alias, line_num)
                    if not is_valid:
                        skipped_count += 1
                        skipped_reasons.append(error_msg)
                        continue
                    
                    # Check for duplicate aliases
                    if alias in out:
                        logger.warning(
                            "Duplicate alias '%s' at line %d; overwriting previous entry",
                            alias,
                            line_num
                        )
                    
                    out[alias] = cred
                
                # Log summary
                logger.info(
                    "Loaded %d valid credential(s) from %s",
                    len(out),
                    os.path.basename(csv_path)
                )
                
                if skipped_count > 0:
                    logger.warning(
                        "Skipped %d incomplete row(s) from %s",
                        skipped_count,
                        os.path.basename(csv_path)
                    )
                    for reason in skipped_reasons[:5]:
                        logger.warning("  %s", reason)
                    if len(skipped_reasons) > 5:
                        logger.warning(
                            "  ... and %d more skipped row(s)",
                            len(skipped_reasons) - 5
                        )
                
                if not out:
                    raise ValueError(
                        f"No valid credentials found in '{csv_path}'. "
                        "Please ensure the file contains valid rows with all required fields."
                    )
                
                # Update cache (thread-safe)
                if use_cache:
                    with _cache_lock:
                        _creds_cache[csv_path] = (out.copy(), datetime.now().timestamp())
                
                # Audit log for credential loading
                log_audit_event(
                    "CREDENTIALS_LOADED",
                    {
                        "file": os.path.basename(csv_path),
                        "count": len(out),
                        "encrypted": encrypted,
                        "skipped": skipped_count
                    },
                    level=logging.INFO
                )
                
                return out
                
        except FileNotFoundError as e:
            logger.error("Credentials file not found: %s", csv_path)
            raise FileNotFoundError(
                f"Credentials file not found: {csv_path}. "
                "Please create the file with your account credentials."
            ) from e
            
        except PermissionError as e:
            logger.error("Permission denied reading credentials file: %s", csv_path)
            raise PermissionError(
                f"Permission denied reading credentials file: {csv_path}. "
                "Please check file permissions."
            ) from e
            
        except csv.Error as e:
            logger.error("CSV parsing error in %s: %s", csv_path, e)
            raise ValueError(
                f"CSV file '{csv_path}' is malformed or corrupted. "
                f"Error: {e}"
            ) from e


# ============================================================
# Migration Utilities
# ============================================================

def migrate_to_encrypted(
    input_csv: str,
    output_csv: str,
    encryption_key: Optional[bytes] = None,
    backup: bool = True
) -> None:
    """
    Migrate unencrypted credentials CSV to encrypted format.
    
    Args:
        input_csv: Path to unencrypted credentials file
        output_csv: Path for encrypted output file
        encryption_key: Encryption key (or use CREDENTIALS_ENCRYPTION_KEY env var)
        backup: Create backup of input file before migration
        
    Raises:
        FileNotFoundError: If input file doesn't exist
        RuntimeError: If encryption key not provided
    """
    with ErrorContext(
        "migrating credentials to encrypted format",
        operation="migrate_credentials",
        reraise=True
    ):
        # Get encryption key
        if encryption_key is None:
            encryption_key = get_encryption_key()
        
        if not encryption_key:
            raise RuntimeError(
                "Encryption key required for migration. "
                "Set CREDENTIALS_ENCRYPTION_KEY environment variable. "
                "Generate with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )
        
        # Create backup if requested
        if backup and os.path.exists(input_csv):
            backup_path = f"{input_csv}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            import shutil
            shutil.copy2(input_csv, backup_path)
            logger.info("Created backup: %s", backup_path)
        
        # Load unencrypted credentials
        logger.info("Loading unencrypted credentials from: %s", input_csv)
        creds = load_creds(input_csv, encrypted=False, use_cache=False)
        
        # Write encrypted credentials
        logger.info("Writing encrypted credentials to: %s", output_csv)
        
        with open(output_csv, "w", newline="", encoding="utf-8") as f:
            fieldnames = [
                "alias",
                "login_id",
                "user_id",
                "username",
                "password_encrypted",
                "account_number"
            ]
            
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for alias, cred in creds.items():
                # Encrypt password
                password_encrypted = encrypt_credential_field(
                    cred["password"],
                    encryption_key
                )
                
                writer.writerow({
                    "alias": cred["alias"],
                    "login_id": cred.get("login_id", ""),
                    "user_id": cred.get("user_id", ""),
                    "username": cred.get("username", ""),
                    "password_encrypted": password_encrypted,
                    "account_number": cred["account_number"]
                })
        
        # Set secure permissions on output file
        os.chmod(output_csv, 0o600)
        logger.info("Set secure permissions (600) on: %s", output_csv)
        
        logger.info("Migration complete: %d credentials encrypted", len(creds))
        logger.warning(
            "SECURITY: Securely delete original file after verifying: shred -u %s",
            input_csv
        )
        
        # Audit log
        log_audit_event(
            "CREDENTIALS_MIGRATED",
            {
                "input_file": os.path.basename(input_csv),
                "output_file": os.path.basename(output_csv),
                "count": len(creds)
            },
            level=logging.INFO
        )


def clear_credentials_cache() -> None:
    """Clear in-memory credentials cache."""
    with _cache_lock:
        count = len(_creds_cache)
        _creds_cache.clear()
        logger.info("Cleared credentials cache (%d entries)", count)


# ============================================================
# CLI Utilities
# ============================================================

if __name__ == "__main__":
    """Command-line utility for credential management."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python -m payatom_bot.creds migrate <input.csv> <output.csv.enc>")
        print("  python -m payatom_bot.creds validate <credentials.csv>")
        print("  python -m payatom_bot.creds check-perms <credentials.csv>")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "migrate":
        if len(sys.argv) != 4:
            print("Usage: python -m payatom_bot.creds migrate <input.csv> <output.csv.enc>")
            sys.exit(1)
        
        input_file = sys.argv[2]
        output_file = sys.argv[3]
        
        try:
            migrate_to_encrypted(input_file, output_file)
            print(f"Successfully migrated {input_file} to {output_file}")
            print(f"Remember to securely delete {input_file} after verification")
        except Exception as e:
            print(f"Migration failed: {e}")
            sys.exit(1)
    
    elif command == "validate":
        if len(sys.argv) != 3:
            print("Usage: python -m payatom_bot.creds validate <credentials.csv>")
            sys.exit(1)
        
        csv_file = sys.argv[2]
        
        try:
            creds = load_creds(csv_file, auto_detect_encryption=True)
            print(f"Valid credentials file with {len(creds)} account(s)")
            for alias, cred in creds.items():
                print(f"   - {alias} ({cred['bank_label']}): ***{cred['account_number'][-4:]}")
        except Exception as e:
            print(f"Validation failed: {e}")
            sys.exit(1)
    
    elif command == "check-perms":
        if len(sys.argv) != 3:
            print("Usage: python -m payatom_bot.creds check-perms <credentials.csv>")
            sys.exit(1)
        
        csv_file = sys.argv[2]
        
        try:
            validate_file_permissions(csv_file, strict=False)
            print(f"File permissions OK for {csv_file}")
        except Exception as e:
            print(f"Permission check: {e}")
            sys.exit(1)
    
    else:
        print(f"Unknown command: {command}")
        print("Valid commands: migrate, validate, check-perms")
        sys.exit(1)