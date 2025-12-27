from __future__ import annotations
import csv
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Map alias suffixes to the exact AutoBank dropdown labels.
# Adjust strings to match your portal's options precisely.
BANK_LABEL_BY_SUFFIX: Dict[str, str] = {
    "_tmb":     "TMB",
    "_iobcorp": "IOB Corporate",
    "_iob":     "IOB",
    "_kgb":     "KGB",
    "_idbi":    "IDBI",
    "_idfc":    "IDFC",
    "_canara":  "CANARA",
    "_cnrb":    "CANARA",
}

def infer_bank_label_from_alias(alias: str) -> str:
    """
    Infer the bank label from alias suffix.
    
    Args:
        alias: The account alias
        
    Returns:
        Bank label string (e.g., "TMB", "IOB Corporate")
    """
    a = alias.lower().strip()
    for suffix, label in BANK_LABEL_BY_SUFFIX.items():
        if a.endswith(suffix):
            return label
    # Fallback: take last token after '_' and uppercase (e.g., foo_xyz -> XYZ)
    if "_" in a:
        return a.rsplit("_", 1)[-1].upper()
    return a.upper()

def canonical_auth_id(username: str, login_id: str, user_id: str) -> Optional[str]:
    """
    Determine the canonical authentication ID from available fields.
    
    Args:
        username: Username field
        login_id: Login ID field
        user_id: User ID field
        
    Returns:
        The first non-empty authentication identifier, or None
    """
    for v in (username or "", login_id or "", user_id or ""):
        v = v.strip()
        if v:
            return v
    return None

def load_creds(csv_path: str) -> Dict[str, dict]:
    """
    Load credentials from CSV file with validation and error handling.
    
    CSV schema:
      alias,login_id,user_id,username,password,account_number
      
    Returns:
        Dictionary mapping alias to credential dict:
        {
            alias: {
                auth_id, password, account_number, bank_label,
                raw: {login_id, user_id, username}
            }
        }
        
    Raises:
        FileNotFoundError: If CSV file doesn't exist
        ValueError: If CSV is malformed or missing required columns
        PermissionError: If CSV file cannot be read
    """
    logger.info("Loading credentials from: %s", csv_path)
    
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            
            # Validate headers
            if not reader.fieldnames:
                raise ValueError(
                    f"❌ CSV file '{csv_path}' appears to be empty or malformed.\n"
                    "Expected columns: alias, login_id, user_id, username, password, account_number"
                )
            
            required = {"alias", "login_id", "user_id", "username", "password", "account_number"}
            headers_lower = {h.lower() for h in reader.fieldnames}
            missing = required - headers_lower
            
            if missing:
                raise ValueError(
                    f"❌ CSV file '{csv_path}' is missing required columns: {', '.join(sorted(missing))}\n"
                    f"Expected columns: {', '.join(sorted(required))}\n"
                    f"Found columns: {', '.join(reader.fieldnames)}"
                )

            out: Dict[str, dict] = {}
            line_num = 1  # header is line 1
            skipped_count = 0
            skipped_reasons: list[str] = []
            
            for row in reader:
                line_num += 1
                alias = (row.get("alias") or "").strip()
                
                if not alias:
                    skipped_count += 1
                    skipped_reasons.append(f"Line {line_num}: Empty alias")
                    continue

                login_id = row.get("login_id") or ""
                user_id = row.get("user_id") or ""
                username = row.get("username") or ""
                password = (row.get("password") or "").strip()
                account_number = (row.get("account_number") or "").strip()

                auth_id = canonical_auth_id(username, login_id, user_id)
                
                # Validate required fields
                if not auth_id:
                    skipped_count += 1
                    skipped_reasons.append(
                        f"Line {line_num} (alias: {alias}): Missing username/login_id/user_id"
                    )
                    continue
                    
                if not password:
                    skipped_count += 1
                    skipped_reasons.append(
                        f"Line {line_num} (alias: {alias}): Missing password"
                    )
                    continue
                    
                if not account_number:
                    skipped_count += 1
                    skipped_reasons.append(
                        f"Line {line_num} (alias: {alias}): Missing account_number"
                    )
                    continue

                # Check for duplicate aliases
                if alias in out:
                    logger.warning(
                        "Duplicate alias '%s' at line %d; overwriting previous entry",
                        alias,
                        line_num
                    )

                bank_label = infer_bank_label_from_alias(alias)

                out[alias] = {
                    "alias": alias,
                    "auth_id": auth_id,
                    "password": password,
                    "account_number": account_number,
                    "bank_label": bank_label,
                    # Keep raw fields in case a specific bank needs them:
                    "login_id": login_id.strip(),
                    "user_id": user_id.strip(),
                    "username": username.strip(),
                }
                
            # Log summary
            logger.info(
                "Loaded %d valid credential(s) from %s",
                len(out),
                csv_path
            )
            
            if skipped_count > 0:
                logger.warning(
                    "Skipped %d incomplete row(s) from %s",
                    skipped_count,
                    csv_path
                )
                for reason in skipped_reasons[:5]:  # Show first 5 reasons
                    logger.warning("  - %s", reason)
                if len(skipped_reasons) > 5:
                    logger.warning(
                        "  ... and %d more skipped rows",
                        len(skipped_reasons) - 5
                    )
            
            if not out:
                raise ValueError(
                    f"❌ No valid credentials found in '{csv_path}'.\n"
                    "Please ensure the file contains valid rows with all required fields."
                )
                
            return out
            
    except FileNotFoundError as e:
        logger.error("Credentials file not found: %s", csv_path)
        raise FileNotFoundError(
            f"❌ Credentials file not found: {csv_path}\n"
            "Please create the file with your account credentials."
        ) from e
        
    except PermissionError as e:
        logger.error("Permission denied reading credentials file: %s", csv_path)
        raise PermissionError(
            f"❌ Permission denied reading credentials file: {csv_path}\n"
            "Please check file permissions."
        ) from e
        
    except csv.Error as e:
        logger.error("CSV parsing error in %s: %s", csv_path, e)
        raise ValueError(
            f"❌ CSV file '{csv_path}' is malformed or corrupted.\n"
            f"Error: {e}\n"
            "Please check the file format."
        ) from e
