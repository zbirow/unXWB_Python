#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    unxwb.py - Konwersja C -> Python programu unxwb 0.3.6 by Luigi Auriemma.

    Ten program jest wolnym oprogramowaniem; możesz go redystrybuować i/lub
    modyfikować na warunkach Powszechnej Licencji Publicznej GNU opublikowanej przez
    Free Software Foundation; albo w wersji 2 tej Licencji, albo
    (według Twojego wyboru) dowolnej późniejszej wersji.

    Ten program jest rozpowszechniany w nadziei, że będzie użyteczny,
    ale BEZ JAKIEJKOLWIEK GWARANCJI; nawet bez domniemanej gwarancji
    PRZYDATNOŚCI HANDLOWEJ lub PRZYDATNOŚCI DO OKREŚLONEGO CELU. Zobacz
    Powszechną Licencję Publiczną GNU, aby uzyskać więcej szczegółów.

    Oryginalny autor C: Luigi Auriemma (aluigi.org)
    Konwersja do Python: Claude/GPT-4
"""

import argparse
import os
import struct
import sys
import zlib
import subprocess
from typing import BinaryIO, Optional, Tuple

# --- Stałe z myxact.h ---
ADPCM_MINIWAVEFORMAT_BLOCKALIGN_CONVERSION_OFFSET = 22

WAVEBANK_HEADER_SIGNATURE = b'DNBW'
WAVEBANK_HEADER_VERSION = 43

WAVEBANK_BANKNAME_LENGTH = 64
WAVEBANK_ENTRYNAME_LENGTH = 64

# Flagi banku
WAVEBANK_TYPE_BUFFER = 0x00000000
WAVEBANK_TYPE_STREAMING = 0x00000001
WAVEBANK_FLAGS_ENTRYNAMES = 0x00010000
WAVEBANK_FLAGS_COMPACT = 0x00020000
WAVEBANK_FLAGS_SYNC_DISABLED = 0x00040000

# Tagi formatu fali
WAVEBANKMINIFORMAT_TAG_PCM = 0x0
WAVEBANKMINIFORMAT_TAG_XMA = 0x1
WAVEBANKMINIFORMAT_TAG_ADPCM = 0x2
WAVEBANKMINIFORMAT_TAG_WMA = 0x3

# Indeksy segmentów
WAVEBANK_SEGIDX_BANKDATA = 0
WAVEBANK_SEGIDX_ENTRYMETADATA = 1
WAVEBANK_SEGIDX_SEEKTABLES = 2
WAVEBANK_SEGIDX_ENTRYNAMES = 3
WAVEBANK_SEGIDX_ENTRYWAVEDATA = 4
WAVEBANK_SEGIDX_COUNT = 5

# --- Stałe z unxwb.c ---
VER = "0.3.6 (Python port)"
XWBSIGNi = b"WBND"
XWBSIGNb = b"DNBW"
WBASIGNi = b"HVSIWBA\0"
WBASIGNb = b"ISVH\0ABW"

# --- Klasy reprezentujące struktury C ---

class WaveBankRegion:
    def __init__(self, offset=0, length=0):
        self.offset = offset
        self.length = length

class WaveBankHeader:
    def __init__(self):
        self.signature = b''
        self.version = 0
        self.segments = [WaveBankRegion() for _ in range(WAVEBANK_SEGIDX_COUNT)]

class WaveBankData:
    def __init__(self):
        self.flags = 0
        self.entry_count = 0
        self.bank_name = b''
        self.entry_meta_data_element_size = 0
        self.entry_name_element_size = 0
        self.alignment = 0
        self.compact_format = 0
        self.build_time = 0

class WaveBankEntry:
    def __init__(self):
        self.flags_and_duration = 0
        self.format = 0
        self.play_region = WaveBankRegion()
        self.loop_region = WaveBankRegion()

# --- Funkcje pomocnicze ---

def show_dump(data: bytes, stream: BinaryIO = sys.stdout):
    """Odpowiednik show_dump z show_dump.h"""
    hex_chars = "0123456789abcdef"
    offset = 0
    while offset < len(data):
        chunk = data[offset:offset+16]
        
        hex_part = ' '.join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(16 * 3 - 1)
        
        char_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        
        line = f"{hex_part}  {char_part}\n"
        stream.buffer.write(line.encode('ascii'))
        offset += 16

def get_num(data: str) -> int:
    """Konwertuje string na liczbę, obsługując formaty dec, hex (0x) i ($)."""
    data = data.lower()
    if data.startswith('0x'):
        return int(data[2:], 16)
    if data.startswith('$'):
        return int(data[1:], 16)
    return int(data)

def overwrite_file(fname: str) -> bool:
    """Pyta użytkownika, czy nadpisać istniejący plik."""
    if not os.path.exists(fname):
        return True
    
    while True:
        try:
            ans = input(f"- Czy chcesz nadpisać plik \"{fname}\"? (y/N/all): ").lower()
            if ans.startswith('y'):
                return True
            if ans.startswith('a'):
                # W tej implementacji 'all' działa jak 'yes' dla jednego pliku.
                # Aby zaimplementować to w pełni, potrzebna byłaby zmienna globalna.
                return True
            return False
        except EOFError:
            return False

def my_exit(ret: int):
    """Zakończenie programu."""
    sys.exit(ret)

# --- Funkcje do zapisu nagłówków (odpowiedniki mywav.h i xma_header.h) ---

def fw_u8(fd: BinaryIO, num: int):
    fd.write(struct.pack('<B', num & 0xFF))

def fw_u16(fd: BinaryIO, num: int):
    fd.write(struct.pack('<H', num & 0xFFFF))

def fw_u32(fd: BinaryIO, num: int):
    fd.write(struct.pack('<I', num & 0xFFFFFFFF))

def fw_mem(fd: BinaryIO, data: bytes):
    fd.write(data)
    
def fw_chunk(fd: BinaryIO, chunk_id: bytes, chunk_size: int):
    fw_mem(fd, chunk_id)
    fw_u32(fd, chunk_size)

def write_pcm_wav_header(fd: BinaryIO, data_size: int, channels: int, sample_rate: int, bits_per_sample: int):
    block_align = (bits_per_sample // 8) * channels
    avg_bytes_per_sec = sample_rate * block_align
    
    # RIFF chunk
    riff_size = 4 + 8 + 16 + 8 + data_size
    fw_mem(fd, b'RIFF')
    fw_u32(fd, riff_size)
    fw_mem(fd, b'WAVE')
    
    # fmt chunk
    fw_chunk(fd, b'fmt ', 16)
    fw_u16(fd, 1) # wFormatTag (PCM)
    fw_u16(fd, channels)
    fw_u32(fd, sample_rate)
    fw_u32(fd, avg_bytes_per_sec)
    fw_u16(fd, block_align)
    fw_u16(fd, bits_per_sample)
    
    # data chunk
    fw_chunk(fd, b'data', data_size)

def write_adpcm_wav_header(fd: BinaryIO, data_size: int, channels: int, sample_rate: int, align: int):
    wFormatTag = 0x0002  # MS ADPCM
    wBitsPerSample = 4

    wBlockAlign = (align + ADPCM_MINIWAVEFORMAT_BLOCKALIGN_CONVERSION_OFFSET) * channels

    ADPCM_COEFFS = 7
    coeff7 = [
        0x00000100, 0xFF000200, 0x00000000, 0x004000C0,
        0x000000F0, 0xFF3001CC, 0xFF180188
    ]
    
    # extra_data_content zawiera TYLKO dane dodatkowe, BEZ pola cbSize
    extra_data_content = bytearray()

    denominator = wBitsPerSample * channels
    dw = (((wBlockAlign - (7 * channels)) * 8) // denominator) + 2 if denominator else 0
    avg_bytes_per_sec = (sample_rate // dw) * wBlockAlign if dw else 0

    extra_data_content += struct.pack('<H', dw)
    extra_data_content += struct.pack('<H', ADPCM_COEFFS)
    for i in range(ADPCM_COEFFS):
        # --- POCZĄTEK POPRAWKI ---
        # Wracamy do zapisu 4 bajtów jako unsigned int.
        # To jest najwierniejsze odtworzenie oryginalnego kodu C (putxx(..., 32))
        # i unika problemów z zakresem signed short.
        extra_data_content += struct.pack('<I', coeff7[i])
        # --- KONIEC POPRAWKI ---
        
    cbSize = len(extra_data_content) # Powinno być 32
    
    # Prawidłowy rozmiar bloku fmt = 16 (standardowe pola) + 2 (cbSize) + 32 (dane dodatkowe) = 50
    fmt_chunk_size = 16 + 2 + cbSize

    # fact chunk
    fact_chunk = bytearray()
    fact_chunk += b'fact'
    fact_chunk += struct.pack('<I', 4)
    if wBlockAlign and channels and wBitsPerSample:
        dw_fact = ((wBlockAlign - (7 * channels)) * 8) // wBitsPerSample
        dw_fact = (data_size // wBlockAlign) * dw_fact
        dw_fact = dw_fact // channels
    else:
        dw_fact = 0
    fact_chunk += struct.pack('<I', dw_fact)

    # RIFF header
    riff_size = 4 + (8 + fmt_chunk_size) + len(fact_chunk) + (8 + data_size)
    
    fw_mem(fd, b'RIFF')
    fw_u32(fd, riff_size)
    fw_mem(fd, b'WAVE')

    # fmt chunk
    fw_chunk(fd, b'fmt ', fmt_chunk_size)
    fw_u16(fd, wFormatTag)
    fw_u16(fd, channels)
    fw_u32(fd, sample_rate)
    fw_u32(fd, avg_bytes_per_sec)
    fw_u16(fd, wBlockAlign)
    fw_u16(fd, wBitsPerSample)
    fw_u16(fd, cbSize)  # Zapisujemy cbSize (wartość 32)
    fw_mem(fd, extra_data_content) # Zapisujemy resztę danych (32 bajty)

    # fact chunk
    fw_mem(fd, fact_chunk)
    
    # data chunk
    fw_chunk(fd, b'data', data_size)

def write_xma2_header(fd: BinaryIO, data_size: int, channels: int, sample_rate: int):
    # Tworzenie uproszczonego nagłówka XMA2, wystarczającego do odtwarzania
    # w niektórych narzędziach, jak vgmstream.
    fmt_size = 52 # sizeof(XMA2WAVEFORMATEX)
    seek_size = 0 # brak tabeli seek
    
    # RIFF header
    riff_size = 4 + (8 + fmt_size) + (8 + seek_size) + (8 + data_size)
    fw_mem(fd, b'RIFF')
    fw_u32(fd, riff_size)
    fw_mem(fd, b'WAVE')

    # fmt chunk
    fw_chunk(fd, b'fmt ', fmt_size)
    fw_u16(fd, 0x0166)  # wFormatTag (XMA2)
    fw_u16(fd, channels)
    fw_u32(fd, sample_rate)
    fw_u32(fd, 0) # nAvgBytesPerSec (nieużywane)
    fw_u16(fd, 4) # nBlockAlign
    fw_u16(fd, 16) # wBitsPerSample
    fw_u16(fd, 34) # cbSize
    
    fw_u16(fd, 1) # NumStreams
    fw_u32(fd, 0) # ChannelMask
    fw_u32(fd, 0) # SamplesEncoded (nieznane)
    fw_u32(fd, 0x10000) # BytesPerBlock
    fw_u32(fd, 0) # PlayBegin
    fw_u32(fd, 0) # PlayLength
    fw_u32(fd, 0) # LoopBegin
    fw_u32(fd, 0) # LoopLength
    fw_u8(fd, 0) # LoopCount
    fw_u8(fd, 3) # EncoderVersion
    fw_u16(fd, 1) # BlockCount

    # seek chunk (pusty)
    fw_chunk(fd, b'seek', seek_size)
    
    # data chunk
    fw_chunk(fd, b'data', data_size)


class UnXWB:
    def __init__(self, args):
        self.args = args
        self.file_offset = args.offset
        self.endian_char = '<' # Little-endian domyślnie
        self.fdinfo = sys.stdout

        if args.stdout:
            self.fdinfo = sys.stderr
        
        # Inicjalizacja do obsługi XSB
        self.fdxsb = None
        if args.xsb_file:
            try:
                self.fdxsb = open(args.xsb_file, "rb")
                print(f"- Otwieram plik XSB   {args.xsb_file}", file=self.fdinfo)
            except IOError:
                print("- Nie znaleziono pliku XSB", file=self.fdinfo)

    def read_u16(self, fd: BinaryIO) -> int:
        return struct.unpack(self.endian_char + 'H', fd.read(2))[0]

    def read_u32(self, fd: BinaryIO) -> int:
        return struct.unpack(self.endian_char + 'I', fd.read(4))[0]

    def run(self):
        try:
            if self.args.xwb_file == '-':
                print("- Otwieram plik         stdin", file=self.fdinfo)
                fd = sys.stdin.buffer
            else:
                print(f"- Otwieram plik         {self.args.xwb_file}", file=self.fdinfo)
                fd = open(self.args.xwb_file, "rb")
        except IOError as e:
            print(f"\nBłąd: Nie można otworzyć pliku: {e}", file=sys.stderr)
            my_exit(1)

        with fd:
            self.process_file(fd)

    def process_file(self, fd: BinaryIO):
        filename = self.args.xwb_file
        
        # ZWB (skompresowany XWB)
        if filename.lower().endswith(".zwb"):
            print("- Rozpakowuję plik ZWB...", file=self.fdinfo)
            fd.seek(4) # Pomiń wersję?
            unpacked_size = self.read_u32(fd)
            compressed_data = fd.read()
            try:
                data = zlib.decompress(compressed_data)
                if len(data) != unpacked_size:
                    print(f"  Ostrzeżenie: Rozmiar po dekompresji ({len(data)}) różni się od oczekiwanego ({unpacked_size})", file=self.fdinfo)
                
                import io
                fd = io.BytesIO(data)
                self.file_offset = 0
            except zlib.error as e:
                print(f"\nBłąd: Problem z dekompresją ZWB: {e}", file=sys.stderr)
                my_exit(1)

        if self.args.raw:
            print("- Pliki będą ekstrahowane w trybie surowym (raw)", file=self.fdinfo)
        else:
            print("- Narzędzie spróbuje dodać nagłówki do ekstrahowanych plików", file=self.fdinfo)
        
        # Sprawdzenie nagłówków SXB/VXB/WBA
        fd.seek(self.file_offset)
        sig_check = fd.read(8)
        if sig_check.startswith(b"SDBK") or sig_check.startswith(b"KBDS"):
            fd.seek(self.file_offset)
            # Wykrycie endian
            if sig_check.startswith(b"KBDS"): self.endian_char = '>'
            offset_jump = self.read_u32(fd)
            self.file_offset += offset_jump
        elif sig_check == WBASIGNi or sig_check == WBASIGNb:
            self.file_offset += 4096

        while True:
            try:
                fd.seek(self.file_offset)
                sig = fd.read(4)
                if not sig:
                    break

                if sig == XWBSIGNi:
                    self.endian_char = '<'
                elif sig == XWBSIGNb:
                    self.endian_char = '>'
                else:
                    print("  Ostrzeżenie: nieprawidłowa sygnatura, skanuję plik...", file=self.fdinfo)
                    offset = self.scan_for_signature(fd)
                    if offset == -1:
                        print("\nBłąd: Nie znaleziono sygnatury XWB.", file=sys.stderr)
                        my_exit(1)
                    self.file_offset += offset
                    print(f"- Znaleziono możliwą sygnaturę pod offsetem 0x{self.file_offset:08x}", file=self.fdinfo)
                    continue
                
                self.parse_xwb(fd)
                # Załóżmy, że jest tylko jeden XWB w pliku, chyba że jest specjalna logika.
                break
            except Exception as e:
                print(f"\nBłąd podczas przetwarzania: {e}", file=sys.stderr)
                import traceback
                traceback.print_exc()
                break
        
        if self.fdxsb:
            self.fdxsb.close()
        print(f"\n- Zakończono.", file=self.fdinfo)


    def scan_for_signature(self, fd: BinaryIO) -> int:
        fd.seek(self.file_offset)
        chunk_size = 4096
        read_bytes = 0
        while True:
            chunk = fd.read(chunk_size)
            if not chunk:
                return -1
            
            pos = chunk.find(XWBSIGNi)
            if pos != -1:
                return read_bytes + pos
            
            pos = chunk.find(XWBSIGNb)
            if pos != -1:
                return read_bytes + pos
                
            read_bytes += len(chunk) - 4 # Zachowaj overlap
            fd.seek(self.file_offset + read_bytes)
    
    def get_xsb_name(self, track_num: int) -> str:
        if not self.fdxsb:
            return f"{track_num:08x}" if self.args.hex_names else f"{track_num:d}"
        
        self.fdxsb.seek(self.args.xsb_offset)
        current_track = 0
        while current_track <= track_num:
            name_bytes = bytearray()
            while True:
                b = self.fdxsb.read(1)
                if not b or b[0] < 32: # Koniec na null lub znaku niedrukowalnym
                    break
                name_bytes.append(b[0])
            
            name = name_bytes.decode('ascii', errors='ignore')
            if not name:
                break
            
            if current_track == track_num:
                return name
            current_track += 1
        
        return f"{track_num:08x}" if self.args.hex_names else f"{track_num:d}"


    def parse_xwb(self, fd: BinaryIO):
        fd.seek(self.file_offset + 4) # Pomiń sygnaturę
        header = WaveBankHeader()
        header.version = self.read_u32(fd)
        if self.args.verbose:
            print(f"- Wersja            {header.version}", file=self.fdinfo)

        last_segment = 4
        if header.version == 1:
            pass # Specjalna obsługa później
        elif header.version <= 3:
            last_segment = 3
        elif header.version >= 42:
            _ = self.read_u32(fd) # Pomiń dwHeaderVersion

        if header.version != 1:
            for i in range(last_segment + 1):
                header.segments[i].offset = self.read_u32(fd)
                header.segments[i].length = self.read_u32(fd)
                if self.args.verbose:
                    print(f"- Segment {i}          offset 0x{header.segments[i].offset:08x}   długość {header.segments[i].length}", file=self.fdinfo)

        if self.args.outdir:
            if not os.path.isdir(self.args.outdir):
                os.makedirs(self.args.outdir)
            os.chdir(self.args.outdir)
            print(f"- Zmieniono katalog na  {self.args.outdir}", file=self.fdinfo)
        
        bank_data = WaveBankData()
        fd.seek(self.file_offset + header.segments[WAVEBANK_SEGIDX_BANKDATA].offset)
        bank_data.flags = self.read_u32(fd)
        bank_data.entry_count = self.read_u32(fd)
        
        name_len = 16 if header.version in [2, 3] else WAVEBANK_BANKNAME_LENGTH
        bank_data.bank_name = fd.read(name_len).strip(b'\0')
        
        if header.version == 1:
            wavebank_offset = fd.tell() - self.file_offset
            bank_data.entry_meta_data_element_size = 20
        else:
            bank_data.entry_meta_data_element_size = self.read_u32(fd)
            bank_data.entry_name_element_size = self.read_u32(fd)
            bank_data.alignment = self.read_u32(fd)
            wavebank_offset = header.segments[WAVEBANK_SEGIDX_ENTRYMETADATA].offset

        if bank_data.flags & WAVEBANK_FLAGS_COMPACT:
            bank_data.compact_format = self.read_u32(fd)
        
        if self.args.verbose:
            print(f"\n- Flagi               0x{bank_data.flags:x}", file=self.fdinfo)
            print(f"- Pliki               {bank_data.entry_count}", file=self.fdinfo)
            print(f"- Nazwa banku         {bank_data.bank_name.decode(errors='ignore')}", file=self.fdinfo)

        print("\n"
              "  długość     fmt   częst. kan. b  nazwa pliku\n"
              "=====================================================================")

        playregion_offset = header.segments[last_segment].offset
        if playregion_offset == 0:
            playregion_offset = wavebank_offset + (bank_data.entry_count * bank_data.entry_meta_data_element_size)

        for i in range(bank_data.entry_count):
            fd.seek(self.file_offset + wavebank_offset + (i * bank_data.entry_meta_data_element_size))
            entry = WaveBankEntry()
            
            if bank_data.flags & WAVEBANK_FLAGS_COMPACT:
                val = self.read_u32(fd)
                entry.format = bank_data.compact_format
                entry.play_region.offset = (val & 0x1FFFFF) * bank_data.alignment
                
                # Obejście do wyliczenia długości
                if i == bank_data.entry_count - 1:
                    next_offset = header.segments[last_segment].length
                else:
                    fd.seek(self.file_offset + wavebank_offset + ((i + 1) * bank_data.entry_meta_data_element_size))
                    next_val = self.read_u32(fd)
                    next_offset = (next_val & 0x1FFFFF) * bank_data.alignment
                
                entry.play_region.length = next_offset - entry.play_region.offset
            else:
                if header.version == 1:
                    entry.format = self.read_u32(fd)
                    entry.play_region.offset = self.read_u32(fd)
                    entry.play_region.length = self.read_u32(fd)
                    entry.loop_region.offset = self.read_u32(fd)
                    entry.loop_region.length = self.read_u32(fd)
                else:
                    meta_size = bank_data.entry_meta_data_element_size
                    if meta_size >= 4: entry.flags_and_duration = self.read_u32(fd)
                    if meta_size >= 8: entry.format = self.read_u32(fd)
                    if meta_size >= 12: entry.play_region.offset = self.read_u32(fd)
                    if meta_size >= 16: entry.play_region.length = self.read_u32(fd)
                    if meta_size >= 20: entry.loop_region.offset = self.read_u32(fd)
                    if meta_size >= 24: entry.loop_region.length = self.read_u32(fd)
            
            entry.play_region.offset += playregion_offset

            # Dekodowanie formatu (bitfields)
            fmt = entry.format
            if header.version == 1:
                codec = (fmt) & 1
                chans = (fmt >> 1) & 7
                rate = (fmt >> 5) & 0x3FFFF
                align = (fmt >> 23) & 0xFF
                bits = (fmt >> 31) & 1
            else: # v2, v3, v42, v43 itd.
                codec = (fmt) & 3
                chans = (fmt >> 2) & 7
                rate = (fmt >> 5) & 0x3FFFF
                align = (fmt >> 23) & 0xFF
                bits = (fmt >> 31) & 1
            
            # Poprawka dla starszych wersji
            if header.version <= 3:
                if codec == WAVEBANKMINIFORMAT_TAG_XMA:
                    codec = WAVEBANKMINIFORMAT_TAG_ADPCM
            
            fname = self.get_xsb_name(i)
            
            codec_str, ext = "???", ".dat"
            if not self.args.raw:
                if codec == WAVEBANKMINIFORMAT_TAG_PCM: codec_str, ext = "PCM", ".wav"
                elif codec == WAVEBANKMINIFORMAT_TAG_XMA: codec_str, ext = "XMA", ".wav"
                elif codec == WAVEBANKMINIFORMAT_TAG_ADPCM: codec_str, ext = "ADP", ".wav"
                elif codec == WAVEBANKMINIFORMAT_TAG_WMA: codec_str, ext = "WMA", ".wma"
            
            out_fname = fname + ext
            
            print(f"  {entry.play_region.length:<10}  {codec_str:<3s} {rate:6} {chans} {16 if bits else 8:<2} {out_fname}")

            if self.args.list:
                continue

            self.extract_file(fd, out_fname, entry.play_region.offset, entry.play_region.length,
                              codec, rate, chans, bits, align)

    def extract_file(self, fd: BinaryIO, fname: str, offset: int, size: int,
                     codec: int, rate: int, chans: int, bits: int, align: int):

        if self.args.stdout:
            fdo = sys.stdout.buffer
        else:
            if not overwrite_file(fname):
                return
            try:
                fdo = open(fname, "wb")
            except IOError as e:
                print(f"\nBłąd: Nie można utworzyć pliku wyjściowego: {e}", file=sys.stderr)
                return
        
        with fdo:
            fd.seek(self.file_offset + offset)
            
            # Sprawdzenie WMA
            if not self.args.raw and codec == WAVEBANKMINIFORMAT_TAG_WMA:
                wma_sig = fd.read(16)
                if wma_sig != b'\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c':
                    codec = WAVEBANKMINIFORMAT_TAG_XMA
                fd.seek(self.file_offset + offset)

            # Zapisz nagłówek
            if not self.args.raw:
                bits_per_sample = 16 if bits else 8
                if chans == 0: chans = 1
                
                if codec == WAVEBANKMINIFORMAT_TAG_PCM:
                    write_pcm_wav_header(fdo, size, chans, rate, bits_per_sample)
                elif codec == WAVEBANKMINIFORMAT_TAG_XMA:
                    write_xma2_header(fdo, size, chans, rate)
                elif codec == WAVEBANKMINIFORMAT_TAG_ADPCM:
                    write_adpcm_wav_header(fdo, size, chans, rate, align)
                # Dla WMA i nieznanych formatów, zapisujemy dane surowe
            
            # Kopiuj dane
            remaining = size
            chunk_size = 65536
            while remaining > 0:
                read_size = min(remaining, chunk_size)
                data = fd.read(read_size)
                if not data:
                    print("\nBłąd: Niespodziewany koniec pliku podczas odczytu danych.", file=sys.stderr)
                    break
                fdo.write(data)
                remaining -= len(data)

        if self.args.run_exec:
            self.run_command(fname)

    def run_command(self, fname: str):
        cmd = self.args.run_exec.replace("#FILE", fname)
        print(f"   Wykonuję: \"{cmd}\"")
        subprocess.run(cmd, shell=True)


def main():
    parser = argparse.ArgumentParser(
        description=f"XWB/ZWB files unpacker {VER}",
        usage="%(prog)s [opcje] <plik.XWB>",
        epilog="Oryginalny autor C: Luigi Auriemma, Konwersja Python: Claude/GPT-4"
    )
    parser.add_argument("xwb_file", help="Plik wejściowy .XWB/.ZWB lub '-' dla stdin")
    parser.add_argument("-l", "--list", action="store_true", help="Wyświetl listę plików bez ich ekstrahowania")
    parser.add_argument("-d", "--outdir", help="Katalog wyjściowy do ekstrakcji plików")
    parser.add_argument("-v", "--verbose", action="store_true", help="Szczegółowe informacje wyjściowe")
    parser.add_argument("-b", "--xsb-file", help="Plik .XSB zawierający nazwy ścieżek audio")
    parser.add_argument("--xsb-offset", type=get_num, default=0, help="Offset w pliku XSB, gdzie zaczynają się nazwy")
    parser.add_argument("-x", "--offset", type=get_num, default=0, help="Offset w pliku wejściowym do odczytu danych XWB")
    parser.add_argument("-r", "--run-exec", help="Uruchom polecenie dla każdego pliku wyjściowego (użyj #FILE jako placeholder)")
    parser.add_argument("-o", "--stdout", action="store_true", help="Wypisz pliki na standardowe wyjście zamiast tworzyć pliki")
    parser.add_argument("-R", "--raw", action="store_true", help="Zapisuj surowe dane bez dodawania nagłówków (domyślnie dodaje nagłówki)")
    parser.add_argument("-D", "--decimal-names", dest="hex_names", action="store_false", help="Nazwy plików w notacji dziesiętnej (domyślnie hex)")

    print(f"\nXWB/ZWB files unpacker {VER}\n"
          f"by Luigi Auriemma (oryginalny autor C)\n"
          f"e-mail: aluigi@autistici.org\n"
          f"web:    aluigi.org\n", file=sys.stderr)

    if len(sys.argv) == 1:
        parser.print_help()
        my_exit(1)

    args = parser.parse_args()

    unxwb = UnXWB(args)
    unxwb.run()

if __name__ == '__main__':
    main()