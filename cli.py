import argparse
import sys
import os
import math
from pathlib import Path
from vault_logic import Vault, VaultError, VaultLockedError, VaultOfflineError

vault = Vault()

def format_time(seconds: float) -> str:
    if seconds <= 0:
        return "UNLOCKED"
    d = math.floor(seconds / (3600 * 24))
    h = math.floor((seconds % (3600 * 24)) / 3600)
    m = math.floor((seconds % 3600) / 60)
    
    parts = []
    if d > 0: parts.append(f"{d}d")
    if h > 0: parts.append(f"{h}h")
    if m > 0: parts.append(f"{m}m")
    if not parts: parts.append("< 1m")
    return " ".join(parts)

def cmd_list(args):
    locks = vault.get_all_locks()
    if not locks:
        print("God's Hands are empty.")
        return
        
    print(f"\nGod's Hands — {len(locks)} Entries")
    print("-" * 50)
    import time
    now = time.time()
    for lock in locks:
        name = lock['name']
        type_ = lock['type'].upper()
        rem = max(0, lock['unlock_timestamp'] - now)
        time_str = format_time(rem)
        print(f"[{type_}] {name:<20} | {time_str:>12}")
    print("-" * 50)

def cmd_lock(args):
    try:
        days = float(args.minutes) / (24 * 60)
        vault.lock(args.name, args.secret, days)
        print(f"SUCCESS: Locked text entry '{args.name}' for {args.minutes} minutes.")
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

def cmd_lock_file(args):
    path = Path(args.path)
    if not path.is_file():
        print(f"ERROR: File not found: {args.path}", file=sys.stderr)
        sys.exit(1)
        
    try:
        days = float(args.minutes) / (24 * 60)
        print(f"Encrypting {path.name}...")
        vault.lock_large(args.name, path, path.name, days)
        print(f"SUCCESS: Locked file '{path.name}' as '{args.name}' for {args.minutes} minutes.")
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

def cmd_unlock(args):
    try:
        result = vault.reveal(args.name)
        if result['type'] == 'large_file':
            # Need to reveal_to_file
            downloads = (Path.home() / 'Downloads').resolve()
            downloads.mkdir(exist_ok=True)
            
            orig_name = result.get('original_filename', 'revealed_file')
            safe_name = Path(orig_name).name
            out_path = downloads / safe_name
            counter = 1
            while out_path.exists():
                stem, suffix = Path(safe_name).stem, Path(safe_name).suffix
                out_path = downloads / f"{stem} ({counter}){suffix}"
                counter += 1
                
            print(f"Decrypting file to: {out_path} ...")
            vault.reveal_to_file(args.name, out_path)
            print(f"SUCCESS: File saved to {out_path}")
        else:
            print(f"--- Secret for '{args.name}' ---")
            print(result['secret'])
            print("-" * 30)
    except VaultLockedError as e:
        print(f"LOCKED: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

def cmd_delete(args):
    try:
        if vault.delete_lock(args.name):
            print(f"SUCCESS: Erased entry '{args.name}'.")
        else:
            print(f"ERROR: Entry '{args.name}' not found.", file=sys.stderr)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="God's Hands Core CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # List
    subparsers.add_parser("list", help="List all entries in the vault")
    
    # Lock Text
    lock_p = subparsers.add_parser("lock", help="Lock a text secret")
    lock_p.add_argument("name", help="Name of the entry")
    lock_p.add_argument("secret", help="The text to lock")
    lock_p.add_argument("minutes", type=float, help="Duration in minutes")
    
    # Lock File
    lock_file_p = subparsers.add_parser("lock-file", help="Lock a file (streaming)")
    lock_file_p.add_argument("name", help="Name of the entry")
    lock_file_p.add_argument("path", help="Path to the file to lock")
    lock_file_p.add_argument("minutes", type=float, help="Duration in minutes")
    
    # Unlock
    unlock_p = subparsers.add_parser("unlock", help="Unlock an entry")
    unlock_p.add_argument("name", help="Name of the entry")
    
    # Delete
    delete_p = subparsers.add_parser("delete", help="Permanently erase an entry")
    delete_p.add_argument("name", help="Name of the entry")
    
    args = parser.parse_args()
    
    if args.command == "list":
        cmd_list(args)
    elif args.command == "lock":
        cmd_lock(args)
    elif args.command == "lock-file":
        cmd_lock_file(args)
    elif args.command == "unlock":
        cmd_unlock(args)
    elif args.command == "delete":
        cmd_delete(args)

if __name__ == "__main__":
    main()
