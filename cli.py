#!/usr/bin/env python3
"""
Dead Drop CLI — Adversarial safe. AES-256-GCM + Shamir's Secret Sharing.

Usage:
    dead_drop_cli.py create --message "secret" -n 5 -k 3 [--output ./drops/]
    dead_drop_cli.py create --file secret.pdf -n 5 -k 3 [--output ./drops/]
    dead_drop_cli.py recover --shares share1.txt share2.txt share3.txt --ciphertext drop.bin -k 3
    dead_drop_cli.py verify --shares share1.txt share2.txt share3.txt
    dead_drop_cli.py inspect --drop ./drops/<drop_id>/

Author: Ava Shakil
Date: 2026-02-24
"""

import argparse
import sys
import os
import json

from dead_drop import dead_drop, crypto


def cmd_create(args):
    """Create a new dead drop."""
    # Get payload
    if args.message:
        payload = args.message.encode('utf-8')
        label = args.label or '(text message)'
    elif args.file:
        if not os.path.exists(args.file):
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            return 1
        payload = open(args.file, 'rb').read()
        label = args.label or os.path.basename(args.file)
    else:
        # Read from stdin
        payload = sys.stdin.buffer.read()
        label = args.label or '(stdin)'
    
    if not payload:
        print("Error: empty payload", file=sys.stderr)
        return 1
    
    n = args.shares
    k = args.threshold
    
    print(f"Creating dead drop: {len(payload)} bytes, {k}-of-{n} threshold")
    print(f"Crypto backend: {crypto.get_backend()}")
    
    drop, shares = dead_drop.create(payload, n=n, k=k, label=label)
    
    print(f"Drop ID: {drop.drop_id}")
    print(f"Ciphertext: {len(drop.ciphertext)} bytes")
    
    # Save to disk
    output_dir = args.output or '.'
    drop_files = dead_drop.save_drop(drop, output_dir)
    share_files = dead_drop.save_shares(
        shares, 
        os.path.join(drop_files['directory'], 'shares'),
        drop.drop_id
    )
    
    print(f"\nDrop saved to: {drop_files['directory']}/")
    print(f"  Metadata:    drop.json")
    print(f"  Ciphertext:  ciphertext.bin")
    print(f"  Shares:      shares/ ({len(share_files)} files)")
    
    print(f"\n{'='*60}")
    print(f"⚠️  DISTRIBUTE SHARES TO TRUSTED PARTIES NOW")
    print(f"⚠️  Need {k} of {n} shares to recover")
    print(f"⚠️  DELETE local shares after distribution!")
    print(f"{'='*60}")
    
    if args.print_shares:
        print(f"\nShares:")
        for i, s in enumerate(shares, 1):
            print(f"  [{i}] {s}")
    
    return 0


def cmd_recover(args):
    """Recover a dead drop from shares + ciphertext."""
    # Load shares
    share_paths = args.shares
    if not share_paths:
        print("Error: no shares provided", file=sys.stderr)
        return 1
    
    shares = dead_drop.load_shares(share_paths)
    
    # Load ciphertext
    if not os.path.exists(args.ciphertext):
        print(f"Error: ciphertext not found: {args.ciphertext}", file=sys.stderr)
        return 1
    
    ct = dead_drop.load_ciphertext(args.ciphertext)
    k = args.threshold
    
    print(f"Recovering with {len(shares)} shares (threshold: {k})")
    
    try:
        plaintext = dead_drop.recover(shares, ct, k=k)
    except ValueError as e:
        print(f"Recovery FAILED: {e}", file=sys.stderr)
        return 1
    
    print(f"Recovery successful! Payload: {len(plaintext)} bytes")
    
    # Output
    if args.output:
        with open(args.output, 'wb') as f:
            f.write(plaintext)
        print(f"Saved to: {args.output}")
    else:
        # Try to print as text, fall back to hex
        try:
            text = plaintext.decode('utf-8')
            print(f"\n--- Payload ---\n{text}\n--- End ---")
        except UnicodeDecodeError:
            print(f"\n(Binary payload, use --output to save to file)")
            print(f"First 64 bytes hex: {plaintext[:64].hex()}")
    
    return 0


def cmd_verify(args):
    """Verify shares without decrypting."""
    shares = dead_drop.load_shares(args.shares)
    result = dead_drop.verify_shares(shares)
    
    print(f"Valid:       {result['valid']}")
    print(f"Drop ID:     {result['drop_id']}")
    print(f"Shares:      {result['share_count']}")
    print(f"Indices:     {result['indices']}")
    
    if result['errors']:
        print(f"\nErrors:")
        for e in result['errors']:
            print(f"  ⚠️  {e}")
    
    return 0 if result['valid'] else 1


def cmd_inspect(args):
    """Inspect a dead drop directory."""
    drop_dir = args.drop
    meta_path = os.path.join(drop_dir, 'drop.json')
    
    if not os.path.exists(meta_path):
        print(f"Error: no drop.json in {drop_dir}", file=sys.stderr)
        return 1
    
    with open(meta_path) as f:
        meta = json.load(f)
    
    print(f"Dead Drop: {meta['drop_id']}")
    print(f"Version:   {meta['version']}")
    print(f"Threshold: {meta['k']}-of-{meta['n']}")
    print(f"Ciphertext: {meta['ciphertext_size']} bytes")
    print(f"Created:   {meta.get('created_at', 'unknown')}")
    
    if meta.get('metadata'):
        m = meta['metadata']
        print(f"\nMetadata:")
        print(f"  Payload size:  {m.get('payload_size', '?')} bytes")
        print(f"  Payload hash:  {m.get('payload_hash', '?')}")
        print(f"  Crypto:        {m.get('crypto_backend', '?')}")
        if m.get('label'):
            print(f"  Label:         {m['label']}")
    
    # Check shares directory
    shares_dir = os.path.join(drop_dir, 'shares')
    if os.path.exists(shares_dir):
        share_count = len([f for f in os.listdir(shares_dir) if f.startswith('share_')])
        print(f"\n⚠️  {share_count} shares still on disk — distribute and delete!")
    
    return 0


def main():
    parser = argparse.ArgumentParser(
        description='Dead Drop — Adversarial safe. AES-256-GCM + Shamir\'s Secret Sharing.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create a text dead drop (3-of-5)
  %(prog)s create --message "The truth is here" -n 5 -k 3 --output ./drops/

  # Create from a file (2-of-3)
  %(prog)s create --file evidence.pdf -n 3 -k 2 --output ./drops/

  # Recover with 3 shares
  %(prog)s recover --shares s1.txt s2.txt s3.txt --ciphertext drop.bin -k 3

  # Verify shares are valid
  %(prog)s verify --shares s1.txt s2.txt s3.txt

  # Inspect a drop
  %(prog)s inspect --drop ./drops/deadbeef01234567/
        """
    )
    
    sub = parser.add_subparsers(dest='command', help='Command')
    
    # Create
    p_create = sub.add_parser('create', help='Create a new dead drop')
    p_create.add_argument('--message', '-m', help='Text message to protect')
    p_create.add_argument('--file', '-f', help='File to protect')
    p_create.add_argument('--shares', '-n', type=int, required=True, help='Total shares (N)')
    p_create.add_argument('--threshold', '-k', type=int, required=True, help='Threshold to recover (K)')
    p_create.add_argument('--output', '-o', help='Output directory (default: current)')
    p_create.add_argument('--label', '-l', help='Human-readable label')
    p_create.add_argument('--print-shares', action='store_true', help='Print shares to stdout')
    
    # Recover
    p_recover = sub.add_parser('recover', help='Recover from shares + ciphertext')
    p_recover.add_argument('--shares', '-s', nargs='+', required=True, help='Share files')
    p_recover.add_argument('--ciphertext', '-c', required=True, help='Ciphertext file')
    p_recover.add_argument('--threshold', '-k', type=int, required=True, help='Threshold (K)')
    p_recover.add_argument('--output', '-o', help='Output file (default: print to stdout)')
    
    # Verify
    p_verify = sub.add_parser('verify', help='Verify shares without decrypting')
    p_verify.add_argument('--shares', '-s', nargs='+', required=True, help='Share files')
    
    # Inspect
    p_inspect = sub.add_parser('inspect', help='Inspect a dead drop')
    p_inspect.add_argument('--drop', '-d', required=True, help='Drop directory')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    handlers = {
        'create': cmd_create,
        'recover': cmd_recover,
        'verify': cmd_verify,
        'inspect': cmd_inspect,
    }
    
    return handlers[args.command](args)


if __name__ == '__main__':
    sys.exit(main())
