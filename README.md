# UnXWB.py - Python port

This is a Python 3 port of **unxwb 0.3.6**, a tool originally written in C by Luigi Auriemma ([aluigi.org](http://aluigi.org/)). It unpacks audio files from Microsoft's XACT Wave Bank files (`.xwb`). This version combines all the original C source files into a single, dependency-free Python script.

## Features

- Extracts audio tracks from `.xwb` files.
- Automatically decompresses `.zwb` (Zlib compressed XWB) files.
- Tries to create playable `.wav` or `.wma` files by adding appropriate headers for PCM, MS-ADPCM, and XMA formats.
- Supports both little-endian and big-endian `.xwb` files.
- Can use an associated `.xsb` (XACT Sound Bank) file to name the extracted tracks.
- Command-line interface compatible with the original C version.
- Cross-platform: works on Windows, macOS, and Linux.

## Requirements

- Python 3.6 or newer.
- No external libraries are needed.

## Usage

The script is run from the command line.

```bash
python unxwb.py [options] <input_file.xwb>
```

### Basic Examples

**List contents of an archive:**
```bash
python unxwb.py -l your_archive.xwb
```

**Extract all tracks to the current directory:**
```bash
python unxwb.py your_archive.xwb
```

**Extract tracks to a specific directory:**
```bash
python unxwb.py -d output_folder your_archive.xwb
```

**Extract tracks using names from a sound bank file:**
```bash
python unxwb.py -b your_sound_bank.xsb your_archive.xwb
```

### All Options

```
usage: unxwb.py [options] <file.XWB>

XWB/ZWB files unpacker 0.3.6 (Python port)

positional arguments:
  xwb_file              Input .XWB/.ZWB file or '-' for stdin

options:
  -h, --help            show this help message and exit
  -l, --list            List files without extracting them
  -d OUTDIR, --outdir OUTDIR
                        Output directory to extract files to
  -v, --verbose         Verbose output
  -b XSB_FILE, --xsb-file XSB_FILE
                        .XSB file containing audio track names
  --xsb-offset XSB_OFFSET
                        Offset in the XSB file where names start
  -x OFFSET, --offset OFFSET
                        Offset in the input file to read XWB data from
  -r RUN_EXEC, --run-exec RUN_EXEC
                        Run a command for each output file (use #FILE as a
                        placeholder)
  -o, --stdout          Dump files to stdout instead of creating files
  -R, --raw             Output raw files (by default, the tool adds headers)
  -D, --decimal-names   Use decimal notation for filenames (default is hex)
```

## Credits

- **Original C version:** Luigi Auriemma ([aluigi.org](http://aluigi.org/))
