#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
eMule cancelled.met generator V1.0
https://github.com/ljt3705/emule-cancelled-met-generator

Usage:
    python gen_canc.py <path> [-bypass SIZE]

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
        # Single block: directly compute MD4 of the whole file
        md4 = get_md4()
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(1024 * 1024)  # read 1MB at a time to update progress
                if not chunk:
                    break
                md4.update(chunk)
                if progress_callback:
                    progress_callback(len(chunk))
        return md4.digest()
    else:
        # Multiple blocks: compute MD4 of each block, then MD4 of the concatenated block hashes
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
        # Compute root MD4 of all block hashes concatenated
        combined = b''.join(block_hashes)
        root_md4 = get_md4()
        root_md4.update(combined)
        return root_md4.digest()


def process_files(file_chunk, seed, pid, lock, queue):
    """
    Worker process: processes a chunk of files.
    Sends two types of messages:
        - hash data: ('HASH', filepath, file_hash, hash_hash)
        - stop marker: ('STOP', None, None, None)
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

            # Compute the file's ed2k hash
            file_hash = compute_ed2k_hash(filepath, progress_callback)

            # Construct HashHash = MD5(seed(4 bytes little-endian) + file_hash(16 bytes))
            seed_bytes = struct.pack('<I', seed)
            data = seed_bytes + file_hash
            hash_hash = hashlib.md5(data).digest()

            # Send both the original hash and the transformed hash back to the main process
            queue.put(('HASH', filepath, file_hash, hash_hash))
        except Exception:
            # Skip any file that causes an exception
            pass
        finally:
            if pbar is not None:
                pbar.close()

    # All files in this chunk processed, send stop marker
    queue.put(('STOP', None, None, None))


def main():
    parser = argparse.ArgumentParser(
        description='eMule cancelled.met generator V1.0\nhttps://github.com/ljt3705/emule-cancelled-met-generatorGenerate\n\neMule cancelled.met file from files in a directory tree.',
        epilog='Example: python gen_canc.py D:\\downloads -bypass 200',
        formatter_class = argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('path', help='Directory to scan (will be traversed recursively)')
    parser.add_argument('-bypass', type=int, default=DEFAULT_MIN_SIZE_MB,
                        help='Skip files smaller than this size (in MB). Default: %d MB' % DEFAULT_MIN_SIZE_MB)
    args = parser.parse_args()

    folder = args.path
    if not os.path.isdir(folder):
        print(f"Error: '{folder}' is not a valid directory.")
        sys.exit(1)

    min_size_bytes = args.bypass * 1024 * 1024

    # Scan for files
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
                # Skip files that cannot be accessed
                continue

    if not files:
        print(f"No files found with size >= {args.bypass} MB.")
        sys.exit(0)

    print(f"Found {len(files)} files:")
    for path, size in files:
        print(f"{path} ({size} bytes)")

    # Generate a random seed (32-bit unsigned, non-zero)
    seed = random.randint(1, 0xFFFFFFFE)

    # Determine number of worker processes
    num_processes = multiprocessing.cpu_count()
    chunk_size = len(files) // num_processes + (1 if len(files) % num_processes else 0)
    chunks = [files[i:i+chunk_size] for i in range(0, len(files), chunk_size)]
    actual_processes = len(chunks)

    manager = multiprocessing.Manager()
    lock = manager.Lock()
    queue = manager.Queue()

    # Start worker processes
    processes = []
    for pid, chunk in enumerate(chunks):
        p = multiprocessing.Process(
            target=process_files,
            args=(chunk, seed, pid, lock, queue)
        )
        p.start()
        processes.append(p)

    # Main process: overall progress bar (displayed below all worker bars)
    overall_pbar = tqdm(
        total=len(files),
        desc="Overall progress",
        position=actual_processes,
        leave=True
    )

    result_data = []  # stores (filepath, file_hash, hash_hash)
    finished = 0
    while finished < actual_processes:
        item = queue.get()
        if item[0] == 'STOP':
            finished += 1
        else:
            _, filepath, file_hash, hash_hash = item
            result_data.append((filepath, file_hash, hash_hash))
            overall_pbar.update(1)

    overall_pbar.close()

    for p in processes:
        p.join()

    # Write cancelled.met
    output_path = os.path.join(folder, "cancelled.met")
    with open(output_path, 'wb') as f:
        f.write(struct.pack('<B', CANCELLED_HEADER))
        f.write(struct.pack('<B', CANCELLED_VERSION))
        f.write(struct.pack('<I', seed))
        f.write(struct.pack('<I', len(result_data)))
        for _, _, hash_hash in result_data:
            f.write(hash_hash)          # 16 bytes HashHash
            f.write(struct.pack('<B', 0))   # TagCount = 0

    print(f"\nGenerated {output_path} with {len(result_data)} entries.")

    # Output original ED2K hashes for verification
    print("\nOriginal ED2K hashes (compare with eMule):")
    for filepath, file_hash, _ in result_data:
        print(f"File: {filepath}")
        print(f"  ED2K hash: {file_hash.hex().upper()}")


if __name__ == '__main__':
    main()