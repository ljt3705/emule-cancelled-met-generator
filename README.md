# emule-cancelled-met-generator
Python utility for generating cancelled.met files compatible with eMule clients.

## Introduction

I like downloading files using different methods such as HTTP, FTP, BitTorrent, etc.  
This tool is designed to help eMule recognize files that have already been downloaded before.

By default, eMule keeps track of files it has processed. When using the search function, these files are shown with different colors and statuses in the “Known” column. For example:
- Downloading files appear in red
- Completed or cancelled files appear in green  

Internally, eMule stores cancelled files in a file called `cancelled.met`.

---

## What This Tool Does

This Python utility generates a `cancelled.met` file **without requiring the original files to be present in eMule**.

Features:
- Scan files under a single directory (e.g. `D:\mydownload`) and generate `cancelled.met`
- Support multiple directories across different disks
- Generate intermediate hash files and merge them later
- Much faster hashing compared to eMule

After generating `cancelled.met`, you can replace your existing one.  
Next time you search in eMule, previously downloaded files will appear as **cancelled**, helping you avoid downloading them again.

---

## Why Not Use `known.met`?

You might ask: why not add everything into `known.met`?

Because:
- Files in `known.met` must exist and be shared
- Sharing a very large number of files (e.g. millions) can cause eMule to crash or become unstable

This tool avoids that limitation by using `cancelled.met` instead.

---

## Usage

### 1. Prepare Python Environment

Make sure Python is installed.

Install dependencies:
```
pip install pycryptodome tqdm
```

---

### 2. Scan Single Directory

Generate `cancelled.met` directly:

```
python gen_canc.py -d "D:\mydown"
```

Output will be saved in the same directory.

---

### 3. Multiple Directories (Recommended for Large Collections)

#### Step 1: Generate intermediate hash files
```
python gen_canc.py -d "D:\mydown1" -save "D:\mydown1\hashes1.txt"
python gen_canc.py -d "E:\mydown2" -save "E:\mydown2\hashes2.txt"
```

#### Step 2: Combine hash files

Using command line:
```
copy hashes1.txt + hashes2.txt combined_hashes.txt
```

Or use any text editor to merge them.

#### Step 3: Generate `cancelled.met`
```
python gen_canc.py -infile combined_hashes.txt -o cancelled.met
```

---

### 4. Advanced Options

For more arguments:
```
python gen_canc.py -h
```

---

This project was developed with assistance from AI tools.
