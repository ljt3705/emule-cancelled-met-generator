#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
eMule cancelled.met generator V2.1
with intermediate hash file support
https://github.com/ljt3705/emule-cancelled-met-generator

Modes:
  1. Scan directories and generate cancelled.met directly:
     python gen_canc.py -d <path> [-bypass SIZE] [-o OUTPUT] [-save HASHFILE]
  2. Generate cancelled.met from precomputed hash file:
     python gen_canc.py -infile HASHFILE [-o OUTPUT] [-seed SEED]

Dependencies:
    pip install pycryptodome tqdm
"""

import os
import sys
import struct
import hashlib
import random
import argparse
import multiprocessing
from tqdm import tqdm

# Constants
BLOCK_SIZE = 9728000                     # ed2k block size (9.28 MB)
DEFAULT_MIN_SIZE_MB = 100                 # default minimum file size in MB
CANCELLED_HEADER = 0x0F                   # header from user's eMule version
CANCELLED_VERSION = 0x01                  # file version


def get_md4():
    """
    Return an MD4 hash object, compatible with different environments.
    Uses hashlib's built-in md4 if available, otherwise tries pycryptodome.
    """
    try:
        return hashlib.new('md4')
    except ValueError:
        try:
            from Crypto.Hash import MD4
            return MD4.new()
        except ImportError:
            raise ImportError(
                "MD4 not available. Please install pycryptodome: pip install pycryptodome"
            )


def compute_ed2k_hash(filepath, progress_callback=None):
    """
    Compute the ed2k hash (MD4 root hash) of a file.
    progress_callback: optional callback receiving bytes read (for progress bar).
    """
    file_size = os.path.getsize(filepath)
    if file_size <= BLOCK_SIZE:
        md4 = get_md4()
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                md4.update(chunk)
                if progress_callback:
                    progress_callback(len(chunk))
        return md4.digest()
    else:
        block_hashes = []
        with open(filepath, 'rb') as f:
            while True:
                block_data = f.read(BLOCK_SIZE)
                if not block_data:
                    break
                block_md4 = get_md4()
                block_md4.update(block_data)
                block_hashes.append(block_md4.digest())
                if progress_callback:
                    progress_callback(len(block_data))
        combined = b''.join(block_hashes)
        root_md4 = get_md4()
        root_md4.update(combined)
        return root_md4.digest()


def process_files(file_chunk, seed, pid, lock, queue):
    """
    Worker process for directory scanning mode.
    Sends ('HASH', filepath, file_hash) to main process.
    """
    tqdm.set_lock(lock)
    for filepath, filesize in file_chunk:
        pbar = None
        try:
            desc = os.path.basename(filepath)[:30]
            pbar = tqdm(
                total=filesize,
                unit='B',
                unit_scale=True,
                desc=desc,
                position=pid,
                leave=False
            )

            def progress_callback(bytes_read):
                pbar.update(bytes_read)

            file_hash = compute_ed2k_hash(filepath, progress_callback)
            queue.put(('HASH', filepath, file_hash))
        except Exception:
            pass
        finally:
            if pbar is not None:
                pbar.close()
    queue.put(('STOP', None, None))


def write_cancelled_met(output_path, seed, hash_hashes):
    """
    Write a cancelled.met file with given seed and list of HashHash (bytes).
    """
    with open(output_path, 'wb') as f:
        f.write(struct.pack('<B', CANCELLED_HEADER))
        f.write(struct.pack('<B', CANCELLED_VERSION))
        f.write(struct.pack('<I', seed))
        f.write(struct.pack('<I', len(hash_hashes)))
        for hh in hash_hashes:
            f.write(hh)
            f.write(struct.pack('<B', 0))   # TagCount = 0


def scan_and_generate(args):
    """Mode 1: scan directory and generate cancelled.met (optionally save hashes)."""
    folder = args.directory
    if not os.path.isdir(folder):
        print(f"Error: '{folder}' is not a valid directory.")
        sys.exit(1)

    min_size_bytes = args.bypass * 1024 * 1024

    print("Scanning files...")
    files = []
    for root, _, filenames in os.walk(folder):
        for name in filenames:
            path = os.path.join(root, name)
            try:
                size = os.path.getsize(path)
                if size >= min_size_bytes:
                    files.append((path, size))
            except OSError:
                continue

    if not files:
        print(f"No files found with size >= {args.bypass} MB.")
        sys.exit(0)

    print(f"Found {len(files)} files.")

    # Generate random seed
    seed = random.randint(1, 0xFFFFFFFE)

    # Multi-processing
    num_processes = multiprocessing.cpu_count()
    chunk_size = len(files) // num_processes + (1 if len(files) % num_processes else 0)
    chunks = [files[i:i+chunk_size] for i in range(0, len(files), chunk_size)]
    actual_processes = len(chunks)

    manager = multiprocessing.Manager()
    lock = manager.Lock()
    queue = manager.Queue()

    processes = []
    for pid, chunk in enumerate(chunks):
        p = multiprocessing.Process(
            target=process_files,
            args=(chunk, seed, pid, lock, queue)
        )
        p.start()
        processes.append(p)

    # Main process: collect results
    overall_pbar = tqdm(
        total=len(files),
        desc="Overall progress",
        position=actual_processes,
        leave=True
    )

    file_hashes = []          # list of (filepath, file_hash)
    finished = 0
    while finished < actual_processes:
        item = queue.get()
        if item[0] == 'STOP':
            finished += 1
        else:
            _, filepath, file_hash = item
            file_hashes.append((filepath, file_hash))
            overall_pbar.update(1)

    overall_pbar.close()
    for p in processes:
        p.join()

    # Compute HashHash for each file
    hash_hashes = []
    seed_bytes = struct.pack('<I', seed)
    for _, file_hash in file_hashes:
        data = seed_bytes + file_hash
        hh = hashlib.md5(data).digest()
        hash_hashes.append(hh)

    # Remove duplicates (HashHash duplicates possible if same file appears multiple times? But paths are unique)
    # Actually duplicate HashHash can happen if two different files have same original hash? Very unlikely, but we deduplicate anyway.
    unique_hh = list(set(hash_hashes))
    unique_hh.sort()

    # Write output .met
    output_path = args.output if args.output else os.path.join(folder, "cancelled.met")
    write_cancelled_met(output_path, seed, unique_hh)
    print(f"\nGenerated {output_path} with {len(unique_hh)} entries (seed={seed}).")

    # If save file requested, write original hashes (hex) to a text file (UTF-8 encoding)
    if args.save:
        with open(args.save, 'w', encoding='utf-8') as f:
            f.write(f"# Seed: {seed}\n")
            f.write(f"# Each line: file_hash (hex) [filepath]\n")
            for filepath, file_hash in file_hashes:
                f.write(f"{file_hash.hex().upper()} # {filepath}\n")
        print(f"Saved original hashes to {args.save}")


def generate_from_hashfile(args):
    """Mode 2: generate cancelled.met from a hash file (UTF-8 encoding assumed)."""
    infile = args.infile
    if not os.path.isfile(infile):
        print(f"Error: '{infile}' is not a file.")
        sys.exit(1)

    # Read hash file (UTF-8)
    file_hashes = []
    with open(infile, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Expect hex hash, optionally followed by comment
            parts = line.split('#', 1)
            hex_hash = parts[0].strip()
            if len(hex_hash) != 32:
                print(f"Warning: line {line_num} invalid hash length, skipped.")
                continue
            try:
                file_hash = bytes.fromhex(hex_hash)
            except ValueError:
                print(f"Warning: line {line_num} invalid hex, skipped.")
                continue
            file_hashes.append(file_hash)

    if not file_hashes:
        print("No valid hashes found in file.")
        sys.exit(1)

    print(f"Loaded {len(file_hashes)} hashes from {infile}.")

    # Seed: either user-provided or random
    if args.seed is not None:
        seed = args.seed
        if seed < 1 or seed > 0xFFFFFFFE:
            print("Seed must be between 1 and 4294967294.")
            sys.exit(1)
    else:
        seed = random.randint(1, 0xFFFFFFFE)
        print(f"Generated random seed: {seed}")

    # Compute HashHash for each file
    seed_bytes = struct.pack('<I', seed)
    hash_hashes = []
    for file_hash in file_hashes:
        data = seed_bytes + file_hash
        hh = hashlib.md5(data).digest()
        hash_hashes.append(hh)

    # Deduplicate
    unique_hh = list(set(hash_hashes))
    unique_hh.sort()

    # Output
    output_path = args.output if args.output else "cancelled.met"
    write_cancelled_met(output_path, seed, unique_hh)
    print(f"Generated {output_path} with {len(unique_hh)} entries (seed={seed}).")


def main():
    parser = argparse.ArgumentParser(
        description='eMule cancelled.met generator V2.1\nwith intermediate hash file support\nhttps://github.com/ljt3705/emule-cancelled-met-generator\n\nGenerate eMule cancelled.met file from files or precomputed hash list.',
        epilog='Examples:\n'
               '  python gen_canc.py -d D:\\downloads -bypass 200 -save hashes.txt\n'
               '  python gen_canc.py -infile hashes.txt -o combined.met -seed 12345',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--directory', metavar='PATH',
                       help='Scan a directory recursively')
    group.add_argument('-infile', metavar='FILE',
                       help='Read original ED2K hashes from a text file (one hex hash per line)')

    parser.add_argument('-bypass', type=int, default=DEFAULT_MIN_SIZE_MB,
                        help='Skip files smaller than this size (in MB). Default: %d MB' % DEFAULT_MIN_SIZE_MB)
    parser.add_argument('-o', '--output', metavar='FILE',
                        help='Output cancelled.met file name (default: cancelled.met in target directory or current dir)')
    parser.add_argument('-save', metavar='FILE',
                        help='Save original ED2K hashes to a text file (only with -d mode)')
    parser.add_argument('-seed', type=int,
                        help='Use specific seed (1..4294967294) for -infile mode. If omitted, random seed generated.')

    args = parser.parse_args()

    if args.directory:
        # Mode 1: scan directory
        scan_and_generate(args)
    elif args.infile:
        # Mode 2: from hash file
        generate_from_hashfile(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()