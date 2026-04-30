#!/usr/bin/env python3
"""
HEXtractor2.py - Unified OS partition extractor for Symbol HEX, BGZ, and APF images.

Handles input formats:
  .hex  Symbol custom Intel HEX (WT4090/PXA270, CE5) - existing format
  .apf  Symbol/Zebra Application Package File — multi-file update container (new)
  .bgz  gzip-compressed NK.bin binary (WT41N0/OMAP4, CE7) - new format

Usage:
    python HEXtractor.py --input <path.hex|path.bgz> [--out DIR]

Defaults:
    --out  extract/<input-stem>/  (relative to current working directory)

Outputs:
    <out>/_meta/base_image.bin    flat partition image
    <out>/_meta/manifest.json     ROMHDR + TOC entries + hashes + format info
    <out>/_meta/unpack.log
    <out>/Windows/<name>          ROM modules (EXEs, DLLs)
    <out>/<wince-path>            ROM data files

BGZ format: gzip( Verify-ASCII-header[128 B] + B000FF\\n NK.bin )
NK.bin:     magic(7) + ImageStart u32LE + ImageLength u32LE
            + {RecordAddr u32, RecordLen u32, RecordData[RecordLen]}*
            + {0x00000000, Checksum u32}

HEX format: Symbol custom Intel HEX with hybrid binary payloads (types 82/84),
            ASCII control records (A0/A1/A3), and Symbol RLE inline compression.

The ROMHDR scanner, TOC walk, and module/file extraction pipeline is identical
for both formats once the flat image is produced.
"""

import struct, json, sys, argparse, hashlib, gzip, ctypes, io, os
from pathlib import Path

# ---------------------------------------------------------------------------
# LZX decompressor (inlined — no external dependency)
# ---------------------------------------------------------------------------

class UnsupportedWindowSizeRange(Exception):
    def __init__(self):
        super().__init__()


class LZXConstants(object):
    PRETREE_NUM_ELEMENTS = 20
    SECONDARY_NUM_ELEMENTS = 249
    ALIGNED_NUM_ELEMENTS = 8
    NUM_PRIMARY_LENGTHS = 7
    NUM_CHARS = 256
    MIN_MATCH = 2
    MAX_MATCH = 257
    NUM_REPEATED_OFFSETS = 3
    MAX_GROWTH = 6144
    E8_DISABLE_THRESHOLD = 32768

    class BlockTypeEnum(object):
        def __init__(self, value):
            self.value = value
        def __eq__(self, other):
            if not isinstance(other, LZXConstants.BlockTypeEnum):
                return False
            return self.value == other.value
        def __ne__(self, other):
            return not self.__eq__(other)
        def __hash__(self):
            return hash(self.value)

    BLOCKTYPE_INVALID      = BlockTypeEnum(0)
    BLOCKTYPE_VERBATIM     = BlockTypeEnum(1)
    BLOCKTYPE_ALIGNED      = BlockTypeEnum(2)
    BLOCKTYPE_UNCOMPRESSED = BlockTypeEnum(3)

    PRETREE_MAXSYMBOLS  = PRETREE_NUM_ELEMENTS
    PRETREE_TABLEBITS   = 6
    PRETREE_MAX_CODEWORD = 16
    MAINTREE_MAXSYMBOLS = NUM_CHARS + (51 << 3)
    MAINTREE_TABLEBITS  = 11
    MAINTREE_MAX_CODEWORD = 16
    LENTREE_MAXSYMBOLS  = SECONDARY_NUM_ELEMENTS
    LENTREE_TABLEBITS   = 10
    LENTREE_MAX_CODEWORD = 16
    ALIGNTREE_MAXSYMBOLS = ALIGNED_NUM_ELEMENTS
    ALIGNTREE_TABLEBITS  = 7
    ALIGNTREE_MAX_CODEWORD = 8
    LENTABLE_SAFETY = 64

    position_slots = [30, 32, 34, 36, 38, 42, 50, 66, 98, 162, 290]
    extra_bits = [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
        9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16, 16,
        17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17
    ]
    position_base = [
        0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512,
        768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768,
        49152, 65536, 98304, 131072, 196608, 262144, 393216, 524288, 655360,
        786432, 917504, 1048576, 1179648, 1310720, 1441792, 1572864, 1703936,
        1835008, 1966080, 2097152
    ]


class LZXState(object):
    def __init__(self, window):
        if window < 15 or window > 21:
            raise UnsupportedWindowSizeRange()
        self.R0 = 1
        self.R1 = 1
        self.R2 = 1
        self.main_elements = LZXConstants.NUM_CHARS + (LZXConstants.position_slots[window - 15] << 3)
        self.header_read = False
        self.block_type = LZXConstants.BLOCKTYPE_INVALID
        self.block_length = 0
        self.block_remaining = 0
        self.frames_read = 0
        self.intel_filesize = 0
        self.intel_curpos = 0
        self.intel_started = False
        self.pretree_table  = [0] * ((1 << LZXConstants.PRETREE_TABLEBITS)   + (LZXConstants.PRETREE_MAXSYMBOLS  << 1))
        self.pretree_len    = [0] * (LZXConstants.PRETREE_MAXSYMBOLS   + LZXConstants.LENTABLE_SAFETY)
        self.maintree_table = [0] * ((1 << LZXConstants.MAINTREE_TABLEBITS)  + (LZXConstants.MAINTREE_MAXSYMBOLS << 1))
        self.maintree_len   = [0] * (LZXConstants.MAINTREE_MAXSYMBOLS  + LZXConstants.LENTABLE_SAFETY)
        self.lentree_table  = [0] * ((1 << LZXConstants.LENTREE_TABLEBITS)   + (LZXConstants.LENTREE_MAXSYMBOLS  << 1))
        self.lentree_len    = [0] * (LZXConstants.LENTREE_MAXSYMBOLS   + LZXConstants.LENTABLE_SAFETY)
        self.aligntree_table = [0] * ((1 << LZXConstants.ALIGNTREE_TABLEBITS) + (LZXConstants.ALIGNTREE_MAXSYMBOLS << 1))
        self.aligntree_len  = [0] * (LZXConstants.ALIGNTREE_MAXSYMBOLS + LZXConstants.LENTABLE_SAFETY)
        self.window_size = 1 << (window & 0x1f)
        self.actual_size = self.window_size
        self.window = bytearray(b'\xDC') * self.window_size
        self.window_posn = 0


class LZXDecoder(object):
    def __init__(self, window):
        self.state = LZXState(window)

    def decompress(self, in_f, in_len, out_f, out_len):
        bit_buf   = LZXDecoder.BitBuffer(in_f)
        start_pos = in_f.tell()
        end_pos   = start_pos + in_len
        togo      = out_len

        if not self.state.header_read:
            intel = bit_buf.read_bits(1)
            if intel == 1:
                i = bit_buf.read_bits(16)
                j = bit_buf.read_bits(16)
                self.state.intel_filesize = (i << 16) | j
            self.state.header_read = True

        while togo > 0:
            if self.state.block_remaining == 0:
                if self.state.block_type == LZXConstants.BLOCKTYPE_UNCOMPRESSED:
                    if (self.state.block_length & 1) == 1:
                        in_f.seek(1, os.SEEK_CUR)
                    self.state.block_type = LZXConstants.BLOCKTYPE_INVALID
                    bit_buf.reset()

                self.state.block_type      = LZXConstants.BlockTypeEnum(bit_buf.read_bits(3))
                self.state.block_length    = bit_buf.read_bits(24)
                self.state.block_remaining = self.state.block_length

                if self.state.block_type == LZXConstants.BLOCKTYPE_ALIGNED:
                    for i in range(0, 8):
                        self.state.aligntree_len[i] = bit_buf.read_bits(3)
                    self.__make_decode_table(LZXConstants.ALIGNTREE_MAXSYMBOLS, LZXConstants.ALIGNTREE_TABLEBITS,
                                             self.state.aligntree_len, self.state.aligntree_table)

                if self.state.block_type == LZXConstants.BLOCKTYPE_VERBATIM or \
                        self.state.block_type == LZXConstants.BLOCKTYPE_ALIGNED:
                    self.__read_lengths(self.state.maintree_len, 0, 256, bit_buf)
                    self.__read_lengths(self.state.maintree_len, 256, self.state.main_elements, bit_buf)
                    LZXDecoder.__make_decode_table(LZXConstants.MAINTREE_MAXSYMBOLS, LZXConstants.MAINTREE_TABLEBITS,
                                                   self.state.maintree_len, self.state.maintree_table)
                    if self.state.maintree_len[0xE8] != 0:
                        self.state.intel_started = True
                    self.__read_lengths(self.state.lentree_len, 0, LZXConstants.SECONDARY_NUM_ELEMENTS, bit_buf)
                    LZXDecoder.__make_decode_table(LZXConstants.LENTREE_MAXSYMBOLS, LZXConstants.LENTREE_TABLEBITS,
                                                   self.state.lentree_len, self.state.lentree_table)
                elif self.state.block_type == LZXConstants.BLOCKTYPE_UNCOMPRESSED:
                    if end_pos <= in_f.tell() + 4:
                        return -1
                    self.state.intel_started = True
                    bit_buf.ensure_bits(16)
                    if bit_buf.bits_left > 16:
                        in_f.seek(-2, os.SEEK_CUR)
                    self.state.R0 = int.from_bytes(in_f.read(4), byteorder='little')
                    self.state.R1 = int.from_bytes(in_f.read(4), byteorder='little')
                    self.state.R2 = int.from_bytes(in_f.read(4), byteorder='little')
                else:
                    return -1

            if in_f.tell() > start_pos + in_len:
                if in_f.tell() > start_pos + in_len + 2 or bit_buf.bits_left < 16:
                    return -1

            togo -= self.state.block_remaining if self.state.block_remaining > togo else togo

            self.state.window_posn &= self.state.window_size - 1
            if self.state.window_posn + self.state.block_remaining > self.state.window_size:
                return -1

            if self.state.block_type == LZXConstants.BLOCKTYPE_VERBATIM or \
                    self.state.block_type == LZXConstants.BLOCKTYPE_ALIGNED:
                self.__decompress_block(bit_buf)
            elif self.state.block_type == LZXConstants.BLOCKTYPE_UNCOMPRESSED:
                if in_f.tell() >= end_pos:
                    return -1
                self.__decompress_uncompress(in_f)
            else:
                return -1

        if togo != 0:
            return -1

        start_window_pos = self.state.window_size if self.state.window_posn == 0 else self.state.window_posn
        start_window_pos -= out_len
        out_f.write(memoryview(self.state.window)[start_window_pos:start_window_pos + out_len])
        self.undo_e8_preprocessing(out_len, out_f)
        return 0

    def undo_e8_preprocessing(self, out_len, out_f):
        if out_len >= 10 and self.state.intel_started:
            out_f.seek(0)
            i = 0
            while i < out_len - 10:
                byte = int.from_bytes(out_f.read(1), byteorder='little')
                if byte == 0xE8:
                    absolute_offset = int.from_bytes(out_f.read(4), byteorder='little', signed=True)
                    if -i <= absolute_offset < self.state.intel_filesize:
                        absolute_offset += -i if absolute_offset >= 0 else self.state.intel_filesize
                        out_f.seek(-4, os.SEEK_CUR)
                        out_f.write(absolute_offset.to_bytes(4, byteorder='little', signed=True))
                    i += 4
                i += 1

    def __read_lengths(self, lens, first, last, bit_buf):
        for x in range(0, 20):
            self.state.pretree_len[x] = bit_buf.read_bits(4)
        LZXDecoder.__make_decode_table(LZXConstants.PRETREE_MAXSYMBOLS, LZXConstants.PRETREE_TABLEBITS,
                                       self.state.pretree_len, self.state.pretree_table)
        x = first
        while x < last:
            z = self.__read_huff_sym_pretree(bit_buf)
            if z == 17:
                y = bit_buf.read_bits(4) + 4
                for _ in range(y):
                    lens[x] = 0
                    x += 1
            elif z == 18:
                y = bit_buf.read_bits(5) + 20
                for _ in range(y):
                    lens[x] = 0
                    x += 1
            elif z == 19:
                y = bit_buf.read_bits(1) + 4
                z = self.__read_huff_sym_pretree(bit_buf)
                z = (lens[x] + 17 - z) % 17
                for _ in range(y):
                    lens[x] = z
                    x += 1
            else:
                z = (lens[x] + 17 - z) % 17
                lens[x] = z
                x += 1

    @staticmethod
    def __read_huff_sym(table, lengths, nsyms, nbits, bit_buf, codeword):
        bit_buf.ensure_bits(codeword)
        i = table[bit_buf.peek_bits(nbits)]
        if i >= nsyms:
            j = 1 << (LZXDecoder.BitBuffer.buffer_num_bits - nbits)
            while True:
                j >>= 1
                i <<= 1
                i |= 1 if (bit_buf.buffer.value & j) != 0 else 0
                if j == 0:
                    return 0
                i = table[i]
                if i < nsyms:
                    break
        j = lengths[i]
        bit_buf.remove_bits(j)
        return i

    def __read_huff_sym_pretree(self, bit_buf):
        return self.__read_huff_sym(self.state.pretree_table, self.state.pretree_len,
                                    LZXConstants.PRETREE_MAXSYMBOLS, LZXConstants.PRETREE_TABLEBITS, bit_buf,
                                    LZXConstants.PRETREE_MAX_CODEWORD)

    def __read_huff_sym_maintree(self, bit_buf):
        return self.__read_huff_sym(self.state.maintree_table, self.state.maintree_len,
                                    LZXConstants.MAINTREE_MAXSYMBOLS, LZXConstants.MAINTREE_TABLEBITS, bit_buf,
                                    LZXConstants.MAINTREE_MAX_CODEWORD)

    def __read_huff_sym_lentree(self, bit_buf):
        return self.__read_huff_sym(self.state.lentree_table, self.state.lentree_len,
                                    LZXConstants.LENTREE_MAXSYMBOLS, LZXConstants.LENTREE_TABLEBITS, bit_buf,
                                    LZXConstants.LENTREE_MAX_CODEWORD)

    def __read_huff_sym_aligntree(self, bit_buf):
        return self.__read_huff_sym(self.state.aligntree_table, self.state.aligntree_len,
                                    LZXConstants.ALIGNTREE_MAXSYMBOLS, LZXConstants.ALIGNTREE_TABLEBITS, bit_buf,
                                    LZXConstants.ALIGNTREE_MAX_CODEWORD)

    @staticmethod
    def __make_decode_table(nsyms, nbits, length, table):
        bit_num     = 1
        pos         = 0
        table_mask  = 1 << nbits
        bit_mask    = table_mask >> 1
        next_symbol = bit_mask
        while bit_num <= nbits:
            for sym in range(nsyms):
                if length[sym] == bit_num:
                    leaf = pos
                    pos += bit_mask
                    if pos > table_mask:
                        return False
                    for _ in range(bit_mask):
                        table[leaf] = sym
                        leaf += 1
            bit_mask >>= 1
            bit_num  += 1
        if pos != table_mask:
            for sym in range(pos, table_mask):
                table[sym] = 0
            pos        <<= 16
            table_mask <<= 16
            bit_mask     = 1 << 15
            while bit_num <= 16:
                for sym in range(nsyms):
                    if length[sym] == bit_num:
                        leaf = pos >> 16
                        for fill in range(bit_num - nbits):
                            if table[leaf] == 0:
                                table[next_symbol << 1]       = 0
                                table[(next_symbol << 1) + 1] = 0
                                table[leaf] = next_symbol
                                next_symbol += 1
                            leaf = table[leaf] << 1
                            if ((pos >> (15 - fill)) & 1) == 1:
                                leaf += 1
                        table[leaf] = sym
                        pos += bit_mask
                        if pos > table_mask:
                            return False
                bit_mask >>= 1
                bit_num  += 1
        if pos == table_mask:
            return True
        for sym in range(nsyms):
            if length[sym] != 0:
                return False
        return True

    def __decompress_block(self, bit_buf):
        while self.state.block_remaining > 0:
            main_element = self.__read_huff_sym_maintree(bit_buf)
            if main_element < LZXConstants.NUM_CHARS:
                self.state.window[self.state.window_posn] = main_element
                self.state.window_posn    += 1
                self.state.block_remaining -= 1
                continue
            main_element  -= LZXConstants.NUM_CHARS
            match_length   = main_element & LZXConstants.NUM_PRIMARY_LENGTHS
            if match_length == LZXConstants.NUM_PRIMARY_LENGTHS:
                length_footer = self.__read_huff_sym_lentree(bit_buf)
                match_length += length_footer
            match_length  += LZXConstants.MIN_MATCH
            match_offset   = main_element >> 3
            if match_offset > 2:
                extra = LZXConstants.extra_bits[match_offset]
                if self.state.block_type == LZXConstants.BLOCKTYPE_ALIGNED and extra >= 3:
                    verbatim_bits  = bit_buf.read_bits(extra - 3)
                    verbatim_bits <<= 3
                    aligned_bits   = self.__read_huff_sym_aligntree(bit_buf)
                else:
                    verbatim_bits = bit_buf.read_bits(extra)
                    aligned_bits  = 0
                match_offset = LZXConstants.position_base[match_offset] + verbatim_bits + aligned_bits - 2
                self.state.R2 = self.state.R1
                self.state.R1 = self.state.R0
                self.state.R0 = match_offset
            elif match_offset == 0:
                match_offset = self.state.R0
            elif match_offset == 1:
                match_offset  = self.state.R1
                self.state.R1 = self.state.R0
                self.state.R0 = match_offset
            else:
                match_offset  = self.state.R2
                self.state.R2 = self.state.R0
                self.state.R0 = match_offset
            rundest = self.state.window_posn
            self.state.block_remaining -= match_length
            if self.state.window_posn >= match_offset:
                runsrc = rundest - match_offset
            else:
                runsrc      = rundest + (self.state.window_size - match_offset)
                copy_length = match_offset - self.state.window_posn
                if copy_length < match_length:
                    match_length -= copy_length
                    self.state.window_posn += copy_length
                    for _ in range(copy_length):
                        self.state.window[rundest] = self.state.window[runsrc]
                        rundest += 1
                        runsrc  += 1
                    runsrc = 0
            self.state.window_posn += match_length
            for _ in range(match_length):
                self.state.window[rundest] = self.state.window[runsrc]
                rundest += 1
                runsrc  += 1

    def __decompress_uncompress(self, in_f):
        in_f.readinto(
            memoryview(self.state.window)[self.state.window_posn:self.state.window_posn + self.state.block_remaining])
        self.state.window_posn += self.state.block_remaining

    class BitBuffer(object):
        buffer_type     = ctypes.c_uint
        buffer_num_bits = ctypes.sizeof(buffer_type) * 8

        def __init__(self, f):
            self.buffer   = LZXDecoder.BitBuffer.buffer_type(0)
            self.bits_left = 0
            self.stream   = f

        def reset(self):
            self.buffer.value = 0
            self.bits_left    = 0

        def ensure_bits(self, bits):
            while self.bits_left < bits:
                lo = self.stream.read(1)
                hi = self.stream.read(1)
                lo = ord(lo) if len(lo) != 0 else 0
                hi = ord(hi) if len(hi) != 0 else 0
                self.buffer.value |= ((hi << 8) | lo) << (LZXDecoder.BitBuffer.buffer_num_bits - 16 - self.bits_left)
                self.bits_left += 16

        def peek_bits(self, bits):
            return self.buffer.value >> (LZXDecoder.BitBuffer.buffer_num_bits - (bits & 0x1f))

        def remove_bits(self, bits):
            self.buffer.value <<= bits
            self.bits_left    -= bits

        def read_bits(self, bits):
            ret = 0
            if bits > 0:
                self.ensure_bits(bits)
                ret = self.peek_bits(bits)
                self.remove_bits(bits)
            return ret


def _bin_decompress_rom(read_buffer, amount, decompressed_buffer):
    in_f             = io.BytesIO(read_buffer)
    out_f            = io.BytesIO()
    window_size      = int.from_bytes(in_f.read(4), byteorder='little')
    decompressed_size = int.from_bytes(in_f.read(4), byteorder='little')
    in_f.read(8)
    decoder = LZXDecoder(window_size)
    status  = decoder.decompress(in_f, amount, out_f, decompressed_size)
    out_f.seek(0)
    decompressed_buffer[:decompressed_size] = out_f.read(decompressed_size)
    return status, decompressed_size


def CEDecompressROM(read_buffer, compressed_size, decompressed_buffer, uncompressed_size, skip, step, blocksize):
    output_position = 0
    block_bits = int(blocksize == 4096) * 2 + 10
    if step != 1 and step != 2:
        return -1
    if ((skip & ((1 << block_bits) - 1)) == 0) and compressed_size > 2:
        num_blocks = int.from_bytes(read_buffer[0:3], byteorder='little')
        if num_blocks == 0:
            num_blocks = 2
        else:
            num_blocks = (num_blocks - 1 >> (block_bits & 0x1f)) + 2
        current_position = num_blocks * 3
        next_position    = skip >> (block_bits & 0x1f)
        if not (current_position <= compressed_size and next_position < num_blocks):
            return -1
        if next_position != 0:
            current_position = int.from_bytes(read_buffer[next_position * 3:next_position * 3 + 3], byteorder='little')
        blocksize         = 0
        compressed_size   = current_position
        input_position    = (next_position + 1) * 3
        for current_block in range(next_position + 1, num_blocks):
            if uncompressed_size == 0:
                break
            current_position = int.from_bytes(read_buffer[input_position:input_position + 3], byteorder='little')
            input_position  += 3
            (status, bytes_processed) = _bin_decompress_rom(
                memoryview(read_buffer)[compressed_size:],
                current_position - compressed_size,
                memoryview(decompressed_buffer)[output_position:])
            if status != 0:
                return -1
            blocksize         += bytes_processed
            output_position   += bytes_processed * step
            uncompressed_size -= bytes_processed
            compressed_size    = current_position
    else:
        return -1
    return blocksize


_CEDecompressROM    = CEDecompressROM
_HAS_WINCE_DECOMPR  = True

IMAGE_SCN_COMPRESSED = 0x00002000

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ROMHDR_SIZE     = 0x54
TOCENTRY_SIZE   = 0x20
FILESENTRY_SIZE = 0x1C
E32_SIZE        = 0x70
O32_SIZE        = 0x18

_NK_MAGIC = b'B000FF\n'

# Module-level base used by va2off.
# For HEX: None → va2off uses the physfirst parameter (flat[0] = physfirst VA).
# For BGZ: set to NK.bin ImageStart → va2off uses ImageStart as flat base.
_BGZ_IMAGE_START = None

DEFAULT_OUT = None

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_PATH = None
_log_lines = []

def log(msg):
    _log_lines.append(msg)
    print(msg)

def save_log(path=None):
    target = path if path is not None else LOG_PATH
    if target is None:
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('\n'.join(_log_lines) + '\n', encoding='utf-8')

# ---------------------------------------------------------------------------
# Symbol RLE decompression (inline, identical to unpack_os_hex.py)
# ---------------------------------------------------------------------------
_HEX_CHARS = set(b'0123456789ABCDEFabcdef')

def decompress_rle(data):
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        if b == 0x7C and i + 3 < n:
            b1, b2 = data[i+1], data[i+2]
            if b1 in _HEX_CHARS and b2 in _HEX_CHARS:
                count = int(chr(b1) + chr(b2), 16)
                fill  = data[i+3]
                out.extend(bytes([fill]) * count)
                i += 4
                continue
        if (b == 0x7E or b == 0x7B) and i + 2 < n:
            b1, b2 = data[i+1], data[i+2]
            if b1 in _HEX_CHARS and b2 in _HEX_CHARS:
                out.append(int(chr(b1) + chr(b2), 16))
                i += 3
                continue
        out.append(b)
        i += 1
    return bytes(out)

# ---------------------------------------------------------------------------
# Address helpers
# ---------------------------------------------------------------------------

def va2off(va, physfirst):
    """Convert a virtual address to a flat image offset.

    HEX flat images: flat[0] = content at physfirst VA, so offset = va - physfirst.
    BGZ flat images: flat[0] = content at NK.bin ImageStart (_BGZ_IMAGE_START).
    When _BGZ_IMAGE_START is set, it is used as the base instead of physfirst.
    On OMAP4/CE7, NK.bin ImageStart == physfirst (SDRAM VAs), so the result is
    identical either way. On PXA270 NOR flash BGZ it would differ — log will show.
    """
    if va >= 0x8C000000:
        va -= 0x0C000000  # PXA270 uncached NOR alias normalisation
    base = _BGZ_IMAGE_START if _BGZ_IMAGE_START is not None else physfirst
    off = va - base
    return off if off >= 0 else None


def read_cstring(data, off, maxlen=260):
    if off is None or off < 0 or off >= len(data):
        return None
    end = data.find(b'\x00', off, off + maxlen)
    if end < 0:
        end = min(off + maxlen, len(data))
    try:
        s = data[off:end].decode('ascii')
        return s if s and all(32 <= ord(c) < 127 for c in s) else None
    except Exception:
        return None


def fat83_valid(component):
    if not component:
        return False
    parts = component.split('.')
    if len(parts) > 2:
        return False
    name = parts[0]
    ext  = parts[1] if len(parts) == 2 else ''
    illegal = set(r'"/\[]:;=, ')
    for c in name + ext:
        if ord(c) < 32 or c in illegal:
            return False
    return len(name) <= 8 and len(ext) <= 3


def validate_fat83_path(path_str):
    if not path_str:
        return False
    parts = path_str.strip('\\').split('\\')
    return all(fat83_valid(p) for p in parts if p)

# ---------------------------------------------------------------------------
# Flat image loaders
# ---------------------------------------------------------------------------

def scan_hex_header(hex_path):
    """Read A0/A1/A3 records to extract partition metadata from a Symbol HEX file."""
    data = Path(hex_path).read_bytes()
    pos = 0
    partition_id   = None
    partition_size = None
    device_target  = 1
    has_a1 = False
    has_a3 = False
    a3_values = []
    first_a3_has_type02 = False
    prev_rt = None

    while pos < len(data):
        while pos < len(data) and data[pos:pos+1] != b':':
            pos += 1
        if pos >= len(data):
            break
        pos += 1
        if pos + 8 > len(data):
            break
        hdr = data[pos:pos+8].decode('ascii', errors='replace')
        bc  = int(hdr[0:2], 16)
        rt  = hdr[6:8]
        pos += 8

        if rt == 'A0':
            raw = bytes.fromhex(data[pos:pos+bc].decode('ascii'))
            partition_id   = raw[0]
            partition_size = struct.unpack('>I', raw[1:5])[0]
            pos += bc + 2
        elif rt == 'A1':
            raw = bytes.fromhex(data[pos:pos+bc].decode('ascii'))
            device_target = raw[0]
            has_a1 = True
            pos += bc + 2
        elif rt == 'A3':
            val = int(data[pos:pos+4].decode('ascii'), 16)
            has_a3 = True
            if len(a3_values) == 0 and prev_rt == '02':
                first_a3_has_type02 = True
            a3_values.append(val)
            pos += 6
        elif rt == '02':
            pos += 6
        elif rt in ('82', '84'):
            pos += bc + 2
        elif rt == '01':
            break
        else:
            pos += bc * 2 + 2

        while pos < len(data) and data[pos:pos+1] in (b'\r', b'\n'):
            pos += 1
        prev_rt = rt

    return dict(
        partition_id        = partition_id,
        partition_size      = partition_size,
        device_target       = device_target,
        has_a1              = has_a1,
        has_a3              = has_a3,
        a3_values           = a3_values,
        first_a3_has_type02 = first_a3_has_type02,
        segment_step        = 0x1000,
        records_per_segment = 512,
        segments_per_a3     = 16,
        record_block_size   = 128,
    )


def load_flat_from_hex(hex_path, partition_size, fill=0xFF):
    """Parse Symbol HEX into a flat image with RLE decompression applied.

    Returns (image_bytes, packed_bin_bytes, addrmap_text).
    Identical to parse_hex_to_flat() in unpack_os_hex.py.
    """
    image = bytearray([fill] * partition_size)
    data  = Path(hex_path).read_bytes()
    pos = 0
    cur_a3 = 0
    cur_seg = 0
    written = 0
    records = 0
    packed = bytearray()
    addrmap_lines = []

    while pos < len(data):
        while pos < len(data) and data[pos:pos+1] != b':':
            pos += 1
        if pos >= len(data):
            break
        pos += 1
        if pos + 8 > len(data):
            break
        hdr  = data[pos:pos+8].decode('ascii', errors='replace')
        bc   = int(hdr[0:2], 16)
        addr = int(hdr[2:6], 16)
        rt   = hdr[6:8]
        pos += 8

        if rt in ('82', '84'):
            chunk        = data[pos:pos+bc]
            pos         += bc + 2
            decompressed = decompress_rle(chunk)
            dlen         = len(decompressed)
            linear       = cur_a3 * 0x100000 + (cur_seg << 4) + addr
            foff         = len(packed)
            packed.extend(decompressed)
            addrmap_lines.append(f'{foff},{linear},{dlen}')
            if 0 <= linear and linear + dlen <= len(image):
                image[linear:linear+dlen] = decompressed
                written += dlen
                records += 1
            elif 0 <= linear < len(image):
                avail = len(image) - linear
                image[linear:linear+avail] = decompressed[:avail]
                written += avail
                records += 1
        elif rt == '02':
            cur_seg = int(data[pos:pos+4].decode('ascii'), 16)
            pos += 6
        elif rt == 'A0':
            pos += bc + 2
        elif rt == 'A1':
            pos += bc + 2
        elif rt == 'A3':
            cur_a3  = int(data[pos:pos+4].decode('ascii'), 16)
            cur_seg = 0
            pos += 6
        elif rt == '01':
            break
        else:
            pos += bc * 2 + 2

        while pos < len(data) and data[pos:pos+1] in (b'\r', b'\n'):
            pos += 1

    log(f'  {records} data records, {written:,} bytes written '
        f'({written * 100 / partition_size:.1f}%)')
    addrmap_text = '\n'.join(addrmap_lines) + ('\n' if addrmap_lines else '')
    return bytes(image), bytes(packed), addrmap_text


def load_flat_from_bgz(bgz_path):
    """Decompress .bgz and extract the CE7 OS flat image.

    BGZ = gzip-compressed file with two concatenated sections:

    Section 1 — NK.bin bootstrap (OMAP4 IBL/SPL loaded into internal SRAM):
      magic(7) + ImageStart u32LE + ImageLength u32LE
      + { RecordAddr u32LE, RecordLen u32LE, RecordData[RecordLen] } * N
      + end-of-records: { 0x00000000, checksum } (CE5) or
                        { 0xFFFFFFFF, 0xFFFFFFFF } (CE7)

    Section 2 — CE7 OS flat image (raw binary, base VA = physfirst in ROMHDR):
      Starts immediately after the NK.bin end-of-records marker.
      Passed directly to the ROMHDR scanner; physfirst is read from ROMHDR.
      _BGZ_IMAGE_START is NOT set — va2off uses physfirst from the ROMHDR.

    Returns (os_flat_bytes, nk_image_start, nk_image_length, nk_nrecords,
             nk_bootstrap_end_off) where nk_bootstrap_end_off is the
             decompressed-file offset at which the OS flat image begins.
    """
    global _BGZ_IMAGE_START

    log(f'  Decompressing {bgz_path.name} ...')
    with gzip.open(str(bgz_path), 'rb') as f:
        raw = f.read()
    log(f'  Decompressed size: {len(raw):,} bytes')

    nk_off = raw.find(_NK_MAGIC)
    if nk_off < 0:
        raise ValueError('B000FF NK.bin magic not found in decompressed BGZ content')
    log(f'  NK.bin bootstrap at decompressed offset 0x{nk_off:X}')

    pos          = nk_off + len(_NK_MAGIC)
    image_start  = struct.unpack_from('<I', raw, pos)[0];  pos += 4
    image_length = struct.unpack_from('<I', raw, pos)[0];  pos += 4

    log(f'  NK.bin ImageStart  = 0x{image_start:08X}  (OMAP4 SRAM bootstrap)')
    log(f'  NK.bin ImageLength = 0x{image_length:08X} ({image_length:,} bytes)')

    nrecords      = 0
    data_written  = 0
    rec0_data     = None
    ecect_physfirst = None
    while pos + 8 <= len(raw):
        rec_addr = struct.unpack_from('<I', raw, pos)[0]
        rec_len  = struct.unpack_from('<I', raw, pos + 4)[0]
        # CE5 end-of-records: {0, checksum}; CE7: {0xFFFFFFFF, 0xFFFFFFFF}
        if rec_addr == 0 or rec_addr == 0xFFFFFFFF:
            pos += 8
            break
        if rec_len > 0x1000000:  # sanity: skip implausibly large records
            log(f'  WARN: implausible NK.bin rec_len=0x{rec_len:08X} at 0x{pos:X}, stopping')
            break
        if nrecords == 0:
            rec0_data = raw[pos + 8 : pos + 8 + rec_len]
        off = rec_addr - image_start
        if 0 <= off < image_length:
            data_written += min(rec_len, image_length - off)
        pos      += 8 + rec_len
        nrecords += 1

    # Extract physfirst from ECECT block in bootstrap rec0.
    # ECECT is a 5-byte tag at rec0[0x44] followed by pRomHdr VA and image_span.
    # physfirst = pRomHdr_VA - image_span.  Present in CE7 RAMIMAGE bootstraps.
    if rec0_data and len(rec0_data) >= 0x50:
        ecect_search_off = rec0_data.find(b'ECECT')
        if ecect_search_off >= 0 and ecect_search_off + 9 <= len(rec0_data):
            prom_hdr_va = struct.unpack_from('<I', rec0_data, ecect_search_off + 4)[0]
            img_span    = struct.unpack_from('<I', rec0_data, ecect_search_off + 8)[0]
            cand        = prom_hdr_va - img_span
            if 0x80000000 <= cand <= 0x90000000:
                ecect_physfirst = cand
                log(f'  ECECT physfirst = 0x{ecect_physfirst:08X}  '
                    f'(pRomHdr=0x{prom_hdr_va:08X}  span=0x{img_span:08X})')

    nk_bootstrap_end_off = pos
    log(f'  {nrecords} NK.bin bootstrap records ({data_written:,} bytes), '
        f'end at decompressed offset 0x{nk_bootstrap_end_off:X}')

    # Everything after the NK.bin end-marker is the CE7 OS flat image.
    # physfirst is read from the ROMHDR inside this blob; _BGZ_IMAGE_START
    # is left None so va2off uses physfirst directly.
    _BGZ_IMAGE_START = None
    os_flat = raw[nk_bootstrap_end_off:]
    log(f'  OS flat image: {len(os_flat):,} bytes '
        f'(decompressed 0x{nk_bootstrap_end_off:X} – 0x{len(raw):X})')

    return bytes(os_flat), image_start, image_length, nrecords, nk_bootstrap_end_off, ecect_physfirst

# ---------------------------------------------------------------------------
# Image analysis helpers (ported from unpack_os_hex.py unchanged)
# ---------------------------------------------------------------------------

def find_free_regions(image, fill=0xFF, min_size=64):
    regions = []
    i = 0
    n = len(image)
    while i < n:
        if image[i] == fill:
            j = i
            while j < n and image[j] == fill:
                j += 1
            if j - i >= min_size:
                regions.append((i, j - i))
            i = j
        else:
            i += 1
    regions.sort(key=lambda r: -r[1])
    return regions


_VALID_E32_MAGIC = {0x012E, 0x012F, 0x212E, 0x212F, 0x0122, 0x2122}

def _is_e32_header(img, off):
    if off < 0 or off + 4 > len(img):
        return False
    magic  = struct.unpack_from('<H', img, off + 2)[0]
    if magic not in _VALID_E32_MAGIC:
        return False
    objcnt = struct.unpack_from('<H', img, off)[0]
    return 1 <= objcnt <= 32


def extract_module_image(img, physfirst, e32_va, o32_va, load_va=0):
    result = dict(bytes=None, sections_total=0, sections_used=0,
                  sections_skipped=0, e32_vsize_bytes=0, reason=None)

    e32_off = va2off(e32_va, physfirst)
    if e32_off is None or e32_off + E32_SIZE > len(img):
        result['reason'] = 'e32_va_unresolved'
        return result

    actual_e32_off = e32_off
    objcnt        = struct.unpack_from('<H', img, actual_e32_off)[0]
    magic_at_off  = struct.unpack_from('<H', img, actual_e32_off + 2)[0]
    if objcnt < 1 or objcnt > 64 or magic_at_off not in _VALID_E32_MAGIC:
        found = False
        for _delta in range(1, 9):
            _probe = e32_off + _delta
            if _probe + E32_SIZE > len(img):
                break
            _mp = struct.unpack_from('<H', img, _probe + 2)[0]
            _cp = struct.unpack_from('<H', img, _probe)[0]
            if _mp in _VALID_E32_MAGIC and 1 <= _cp <= 64:
                actual_e32_off = _probe
                objcnt         = _cp
                found          = True
                break
        if not found:
            result['reason'] = f'invalid_objcnt={objcnt}'
            return result

    _vsize_a = struct.unpack_from('<I', img, e32_off + 0x14)[0]
    if actual_e32_off != e32_off:
        _vsize_b   = struct.unpack_from('<I', img, actual_e32_off + 0x14)[0]
        _plausible = [v for v in (_vsize_a, _vsize_b) if 0x1000 <= v <= 0x4000000]
        e32_vsize  = max(_plausible) if _plausible else max(_vsize_a, _vsize_b)
    else:
        e32_vsize = _vsize_a
    result['e32_vsize_bytes'] = e32_vsize
    result['sections_total']  = objcnt

    e32 = dict(
        objcnt      = objcnt,
        imageflags  = struct.unpack_from('<H', img, actual_e32_off + 2)[0],
        entryrva    = struct.unpack_from('<I', img, actual_e32_off + 4)[0],
        vbase       = struct.unpack_from('<I', img, actual_e32_off + 8)[0],
        subsysmajor = struct.unpack_from('<H', img, actual_e32_off + 0x0C)[0],
        subsysminor = struct.unpack_from('<H', img, actual_e32_off + 0x0E)[0],
        stackmax    = struct.unpack_from('<I', img, actual_e32_off + 0x10)[0],
        stackinit   = struct.unpack_from('<I', img, actual_e32_off + 0x14)[0],
        subsys      = struct.unpack_from('<H', img, actual_e32_off + 0x18)[0],
        unit        = [struct.unpack_from('<II', img, actual_e32_off + 0x20 + i*8)
                       for i in range(9)],
        filetype    = struct.unpack_from('<I', img, actual_e32_off + 0x6C)[0],
    )
    result['e32'] = e32

    o32_off_raw = va2off(o32_va, physfirst)
    o32_off     = o32_off_raw
    if o32_off is not None and o32_off + O32_SIZE <= len(img):
        probe = o32_off
        if _is_e32_header(img, probe):
            o32_off = actual_e32_off + E32_SIZE
    if o32_off is None:
        o32_off = actual_e32_off + E32_SIZE

    valid        = []
    section_data = []
    used         = 0
    for i in range(objcnt):
        so     = o32_off + i * O32_SIZE
        if so + O32_SIZE > len(img):
            break
        vsize    = struct.unpack_from('<I', img, so)[0]
        rva      = struct.unpack_from('<I', img, so + 4)[0]
        psize    = struct.unpack_from('<I', img, so + 8)[0]    # o32_psize: compressed size in ROM
        data_va  = struct.unpack_from('<I', img, so + 0x0C)[0] # o32_dataptr: VA of data in ROM
        realaddr = struct.unpack_from('<I', img, so + 0x10)[0] # o32_realaddr: load VA
        flags    = struct.unpack_from('<I', img, so + 0x14)[0] # o32_flags: section characteristics
        fsize    = psize                                        # bytes to read from ROM
        if vsize == 0 or vsize > 0x4000000:
            continue
        section = dict(vsize=vsize, rva=rva, fsize=fsize, flags=flags, data_va=data_va, realaddr=realaddr)
        valid.append(section)
        doff = va2off(data_va, physfirst) if data_va else None
        if flags & IMAGE_SCN_COMPRESSED and _HAS_WINCE_DECOMPR and doff is not None and psize < vsize:
            try:
                decomp_buf = bytearray(vsize + 4096)
                decsz = _CEDecompressROM(bytes(img[doff:doff+psize]), psize, decomp_buf, vsize, 0, 1, 4096)
                if decsz > 0:
                    section_data.append(bytes(decomp_buf[:decsz]))
                    used += 1
                    continue
            except Exception:
                pass
        if doff is not None and doff + fsize <= len(img):
            section_data.append(bytes(img[doff:doff+fsize]))
            used += 1
        else:
            section_data.append(b'')
            result['sections_skipped'] += 1

    result['sections_used']    = used
    result['valid_sections']   = valid
    result['section_data']     = section_data

    if not valid:
        result['reason'] = 'no_valid_sections'
        return result

    module_img = bytearray(e32_vsize)
    for i, s in enumerate(valid):
        sd    = section_data[i] if i < len(section_data) else b''
        start = s['rva']
        end   = min(start + len(sd), e32_vsize)
        if start < e32_vsize and sd:
            module_img[start:end] = sd[:end - start]

    if result['sections_skipped'] > 0:
        lva_off = va2off(load_va, physfirst) if load_va else None
        if lva_off is not None:
            lva_img = img[lva_off:lva_off + e32_vsize]
            gaps = [(s['rva'], s['rva'] + s['vsize'])
                    for s in valid
                    if not section_data[valid.index(s)]]
            gap_bytes = 0
            for gap_start, gap_end in gaps:
                if gap_end > len(lva_img):
                    continue
                chunk = lva_img[gap_start:gap_end]
                if not all(b == 0xFF for b in chunk) and not all(b == 0 for b in chunk):
                    module_img[gap_start:gap_end] = chunk
                    gap_bytes += gap_end - gap_start
            if gap_bytes > 0 or not gaps:
                result['sections_skipped'] = 0
                result['sections_used']    = objcnt

    nonzero = sum(1 for b in module_img if b != 0)
    if nonzero < 16:
        result['reason'] = f'too_few_nonzero={nonzero}'
        return result

    sec_data = []
    for s in valid:
        start = s['rva']
        end   = min(start + s['vsize'], len(module_img))
        sec_data.append(bytes(module_img[start:end]) if end > start else b'')
    result['valid_sections'] = valid
    result['section_data']   = sec_data
    result['bytes']          = bytes(module_img)
    if result['sections_skipped'] > 0:
        result['reason'] = (f'partial_extract: {used}/{result["sections_total"]} sections')
    return result


_PE_FILE_ALIGN = 0x200
_PE_SECT_ALIGN = 0x1000
_IMAGE_FILE_RELOCS_STRIPPED     = 0x0001
_IMAGE_SCN_CNT_CODE             = 0x00000020
_IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
_IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
_SECTION_NAMES = ['.text', '.data', '.pdata', '.rsrc', '.other']
_ST_TEXT, _ST_DATA, _ST_PDATA, _ST_RSRC, _ST_OTHER = range(5)


def build_pe_from_rom_module(e32, valid_sections, section_data, cpu_type):
    objcnt = len(valid_sections)
    if objcnt == 0:
        return b''

    mz = bytearray(0xC0)
    struct.pack_into('<H', mz, 0x00, 0x5A4D)
    struct.pack_into('<H', mz, 0x02, 0x0090)
    struct.pack_into('<H', mz, 0x04, 0x0003)
    struct.pack_into('<H', mz, 0x08, 0x0004)
    struct.pack_into('<H', mz, 0x0C, 0xFFFF)
    struct.pack_into('<H', mz, 0x10, 0x00B8)
    struct.pack_into('<H', mz, 0x18, 0x0040)
    struct.pack_into('<I', mz, 0x3C, 0x00C0)
    mz[0x40:0x80] = bytes([
        0x0E,0x1F,0xBA,0x0E,0x00,0xB4,0x09,0xCD,0x21,0xB8,0x01,0x4C,0xCD,0x21,0x54,0x68,
        0x69,0x73,0x20,0x70,0x72,0x6F,0x67,0x72,0x61,0x6D,0x20,0x63,0x61,0x6E,0x6E,0x6F,
        0x74,0x20,0x62,0x65,0x20,0x72,0x75,0x6E,0x20,0x69,0x6E,0x20,0x44,0x4F,0x53,0x20,
        0x6D,0x6F,0x64,0x65,0x2E,0x0D,0x0D,0x0A,0x24,0x00,0x00,0x00,0x00,0x00,0x00,0x00])

    coff = bytearray(24)
    coff[0:4] = b'PE\x00\x00'
    struct.pack_into('<H', coff,  4, cpu_type)
    struct.pack_into('<H', coff,  6, objcnt)
    struct.pack_into('<H', coff, 20, 0xE0)
    struct.pack_into('<H', coff, 22, e32['imageflags'] | _IMAGE_FILE_RELOCS_STRIPPED)

    opt   = bytearray(0xE0)
    units = e32.get('unit', [])
    struct.pack_into('<H', opt, 0x00, 0x010B)
    struct.pack_into('<I', opt, 0x10, e32.get('stackinit', 0))
    struct.pack_into('<I', opt, 0x14, e32.get('stackmax', 0))
    struct.pack_into('<I', opt, 0x18, e32.get('vbase', 0))
    struct.pack_into('<H', opt, 0x28, e32.get('subsys', 9))
    struct.pack_into('<H', opt, 0x2A, e32.get('subsysmajor', 5))
    struct.pack_into('<I', opt, 0x38, _PE_SECT_ALIGN)
    struct.pack_into('<I', opt, 0x3C, _PE_FILE_ALIGN)
    struct.pack_into('<H', opt, 0x40, e32.get('subsysmajor', 5))
    struct.pack_into('<I', opt, 0x10, e32.get('entryrva', 0))
    if len(units) >= 1:
        struct.pack_into('<I', opt, 0x60, units[0][0])
        struct.pack_into('<I', opt, 0x64, units[0][1])
    if len(units) >= 2:
        struct.pack_into('<I', opt, 0x68, units[1][0])
        struct.pack_into('<I', opt, 0x6C, units[1][1])

    sec_table = bytearray(objcnt * 40)
    file_offset = 0xC0 + 24 + 0xE0 + objcnt * 40
    file_offset = (file_offset + _PE_FILE_ALIGN - 1) & ~(_PE_FILE_ALIGN - 1)
    total_vsize = 0
    for i, s in enumerate(valid_sections):
        so       = i * 40
        sd       = section_data[i] if i < len(section_data) and section_data[i] else b''
        rawsz    = (len(sd) + _PE_FILE_ALIGN - 1) & ~(_PE_FILE_ALIGN - 1)
        sname    = _SECTION_NAMES[min(i, len(_SECTION_NAMES)-1)].encode().ljust(8, b'\x00')
        sec_table[so:so+8] = sname
        struct.pack_into('<I', sec_table, so + 8,  s['vsize'])
        struct.pack_into('<I', sec_table, so + 12, s['rva'])
        struct.pack_into('<I', sec_table, so + 16, rawsz)
        struct.pack_into('<I', sec_table, so + 20, file_offset if sd else 0)
        struct.pack_into('<I', sec_table, so + 36, s.get('flags', _IMAGE_SCN_CNT_CODE))
        if sd:
            file_offset += rawsz
        total_vsize = max(total_vsize, s['rva'] + s['vsize'])

    struct.pack_into('<I', opt, 0x50, total_vsize)
    hdr_size = (0xC0 + 24 + 0xE0 + objcnt * 40 + _PE_FILE_ALIGN - 1) & ~(_PE_FILE_ALIGN-1)
    struct.pack_into('<I', opt, 0x54, hdr_size)

    pe = bytearray(mz) + bytearray(coff) + bytearray(opt) + bytearray(sec_table)
    hdr_aligned = (len(pe) + _PE_FILE_ALIGN - 1) & ~(_PE_FILE_ALIGN - 1)
    if len(pe) < hdr_aligned:
        pe.extend(b'\x00' * (hdr_aligned - len(pe)))

    for i in range(objcnt):
        sd  = section_data[i] if i < len(section_data) and section_data[i] else b''
        pe.extend(sd)
        pad = ((len(sd) + _PE_FILE_ALIGN - 1) & ~(_PE_FILE_ALIGN - 1)) - len(sd)
        if pad > 0:
            pe.extend(b'\x00' * pad)

    return bytes(pe)


def parse_romhdr(img, off):
    if off + ROMHDR_SIZE > len(img):
        return None
    return dict(
        physfirst = struct.unpack_from('<I', img, off + 0x08)[0],
        physlast  = struct.unpack_from('<I', img, off + 0x0C)[0],
        nummods   = struct.unpack_from('<I', img, off + 0x10)[0],
        ptoc      = struct.unpack_from('<I', img, off + 0x14)[0],
        numfiles  = struct.unpack_from('<I', img, off + 0x30)[0],
        cpu       = struct.unpack_from('<H', img, off + 0x44)[0],
    )


_PE_MACHINE_NAMES = {0x01C0:'ARM', 0x01C2:'ARM-Thumb', 0x01C4:'ARM-Thumb2',
                     0x014C:'i386', 0x0200:'IA64', 0x8664:'x64'}


def scan_pe_headers(img):
    results  = []
    img_len  = len(img)
    pos      = 0
    while pos < img_len - 0x40:
        idx = img.find(b'MZ', pos)
        if idx == -1:
            break
        pos = idx + 1
        if idx + 0x40 > img_len:
            continue
        pe_ptr = struct.unpack_from('<I', img, idx + 0x3C)[0]
        if pe_ptr == 0 or pe_ptr >= 0x1000:
            continue
        pe_off = idx + pe_ptr
        if pe_off + 24 > img_len or img[pe_off:pe_off+4] != b'PE\x00\x00':
            continue
        machine       = struct.unpack_from('<H', img, pe_off + 4)[0]
        num_sections  = struct.unpack_from('<H', img, pe_off + 6)[0]
        opt_hdr_size  = struct.unpack_from('<H', img, pe_off + 20)[0]
        chars         = struct.unpack_from('<H', img, pe_off + 22)[0]
        is_dll        = bool(chars & 0x2000)
        if num_sections == 0 or num_sections > 96:
            continue
        opt_off = pe_off + 24
        if opt_off + opt_hdr_size > img_len:
            continue
        size_of_image = export_rva = export_size = 0
        if opt_hdr_size >= 60:
            size_of_image = struct.unpack_from('<I', img, opt_off + 56)[0]
        if opt_hdr_size >= 104:
            export_rva  = struct.unpack_from('<I', img, opt_off + 96)[0]
            export_size = struct.unpack_from('<I', img, opt_off + 100)[0]
        sec_table_off = opt_off + opt_hdr_size
        if sec_table_off + num_sections * 40 > img_len:
            continue
        raw_size  = 0
        sections  = []
        for si in range(num_sections):
            so      = sec_table_off + si * 40
            s_vsize = struct.unpack_from('<I', img, so + 8)[0]
            s_rva   = struct.unpack_from('<I', img, so + 12)[0]
            s_rawsz = struct.unpack_from('<I', img, so + 16)[0]
            s_rawptr= struct.unpack_from('<I', img, so + 20)[0]
            sections.append(dict(vsize=s_vsize, rva=s_rva, rawsz=s_rawsz, rawptr=s_rawptr))
            if s_rawptr > 0 and s_rawsz > 0:
                end = s_rawptr + s_rawsz
                if end > raw_size:
                    raw_size = end
        if raw_size == 0:
            raw_size = size_of_image if size_of_image > 0 else 0x1000
        name = None
        if export_rva > 0 and export_size >= 40:
            for sec in sections:
                if sec['rva'] <= export_rva < sec['rva'] + max(sec['vsize'], sec['rawsz']):
                    exp_file_off = idx + export_rva - sec['rva'] + sec['rawptr']
                    if exp_file_off + 40 <= img_len:
                        name_rva     = struct.unpack_from('<I', img, exp_file_off + 12)[0]
                        if name_rva > 0:
                            name_file_off = idx + name_rva - sec['rva'] + sec['rawptr']
                            if 0 <= name_file_off < img_len:
                                name = read_cstring(img, name_file_off)
                    break
        if name is None and is_dll:
            scan_start = max(0, idx)
            scan_end   = min(img_len, idx + raw_size + 0x1000)
            for dll_marker in (b'.dll\x00', b'.DLL\x00'):
                mi = img.find(dll_marker, scan_start, scan_end)
                while mi != -1:
                    ns = mi
                    while ns > scan_start and img[ns-1:ns] != b'\x00' and \
                          img[ns-1] >= 0x20 and img[ns-1] < 0x7F:
                        ns -= 1
                    candidate = read_cstring(img, ns)
                    if candidate and '.' in candidate and len(candidate) <= 60:
                        name = candidate
                        break
                    mi = img.find(dll_marker, mi + 1, scan_end)
                if name:
                    break
        results.append(dict(
            offset=idx, pe_offset=pe_off, machine=machine,
            num_sections=num_sections, characteristics=chars, is_dll=is_dll,
            size_of_image=size_of_image, raw_size=raw_size, name=name, sections=sections,
        ))
    results.sort(key=lambda p: p['offset'])
    for i in range(len(results) - 1):
        cur = results[i]; nxt = results[i+1]
        if cur['offset'] + cur['raw_size'] > nxt['offset']:
            cur['raw_size'] = nxt['offset'] - cur['offset']
    return results


def detect_flashfx(img):
    offsets = []
    pos     = 0
    while True:
        idx = img.find(b'DL_FS3.00', pos)
        if idx == -1:
            break
        offsets.append(idx)
        pos = idx + 1
    return offsets


# ---------------------------------------------------------------------------
# CE7 RAMIMAGE: direct e32_rom scan and extraction (no ROMHDR required)
# ---------------------------------------------------------------------------

def _get_module_name_from_e32(img, e32_off, physfirst, objcnt, unit):
    """Extract DLL/EXE name from e32_rom export directory."""
    export_rva = unit[0][0]
    if export_rva == 0:
        return None
    img_len = len(img)

    # Attempt 1: export dir at e32_off + export_rva (contiguous module layout)
    exp_flat = e32_off + export_rva
    if 0 <= exp_flat + 40 <= img_len:
        name_field = struct.unpack_from('<I', img, exp_flat + 0x0C)[0]
        if 0x80000000 <= name_field <= 0x90000000:
            name = read_cstring(img, name_field - physfirst)
            if name and '.' in name and len(name) <= 80:
                return name
        if 0 < name_field < 0x4000000:
            name = read_cstring(img, e32_off + name_field)
            if name and '.' in name and len(name) <= 80:
                return name

    # Attempt 2: walk o32_rom sections to locate the one containing export_rva
    o32_base = e32_off + E32_SIZE
    for i in range(objcnt):
        so = o32_base + i * O32_SIZE
        if so + O32_SIZE > img_len:
            break
        vsize   = struct.unpack_from('<I', img, so)[0]
        rva     = struct.unpack_from('<I', img, so + 4)[0]
        data_va = struct.unpack_from('<I', img, so + 0x0C)[0]
        if vsize == 0 or vsize > 0x4000000:
            continue
        if not (rva <= export_rva < rva + vsize):
            continue
        if not (0x80000000 <= data_va <= 0x90000000):
            continue
        exp_flat2 = (data_va - physfirst) + (export_rva - rva)
        if 0 <= exp_flat2 + 40 <= img_len:
            name_field = struct.unpack_from('<I', img, exp_flat2 + 0x0C)[0]
            if 0x80000000 <= name_field <= 0x90000000:
                name = read_cstring(img, name_field - physfirst)
                if name and '.' in name and len(name) <= 80:
                    return name
            if 0 < name_field < 0x4000000:
                sect_flat = data_va - physfirst
                name = read_cstring(img, sect_flat + (name_field - rva))
                if name and '.' in name and len(name) <= 80:
                    return name
        break
    return None


def scan_e32_modules_direct(img, physfirst):
    """Find all e32_rom module headers in a CE7 RAMIMAGE flat.

    Scans for magic {0x012E,0x012F,0x212E,0x212F} at e32+2, validates
    objcnt/vbase/entryrva, and enforces vbase == physfirst + e32_off.
    Returns list of dicts sorted by e32_off.
    """
    results   = []
    seen      = set()
    img_bytes = bytes(img) if isinstance(img, bytearray) else img
    img_len   = len(img)
    for magic_val in _VALID_E32_MAGIC:
        magic_bytes = struct.pack('<H', magic_val)
        pos = 0
        while True:
            idx = img_bytes.find(magic_bytes, pos)
            if idx < 0:
                break
            pos     = idx + 1
            e32_off = idx - 2
            if e32_off < 0 or e32_off + E32_SIZE > img_len:
                continue
            if e32_off in seen:
                continue
            objcnt = struct.unpack_from('<H', img, e32_off)[0]
            if not (1 <= objcnt <= 32):
                continue
            vbase = struct.unpack_from('<I', img, e32_off + 8)[0]
            if not (0x80000000 <= vbase <= 0x90000000):
                continue
            if vbase - physfirst != e32_off:
                continue
            entryrva = struct.unpack_from('<I', img, e32_off + 4)[0]
            if entryrva >= 0x4000000:
                continue
            seen.add(e32_off)
            # unit = [struct.unpack_from('<II', img, e32_off + 0x1C + i*8)  # old: wrong offset/count
            #         for i in range(12)]
            unit = [struct.unpack_from('<II', img, e32_off + 0x20 + i*8)
                    for i in range(9)]
            name = _get_module_name_from_e32(img, e32_off, physfirst, objcnt, unit)
            results.append(dict(e32_off=e32_off, vbase=vbase, objcnt=objcnt,
                                imageflags=magic_val, entryrva=entryrva,
                                unit=unit, name=name))
    results.sort(key=lambda r: r['e32_off'])
    return results


def extract_e32_modules_direct(img, physfirst, out_dir, meta_dir, cpu_type=0x01C4):
    """Extract CE7 RAMIMAGE modules via direct e32_rom scan (no ROMHDR required).

    Calls scan_e32_modules_direct() then the existing extract_module_image()
    + build_pe_from_rom_module() pipeline. Writes to out_dir/Windows/.
    Returns list of module result dicts.
    """
    log(f'  Scanning flat for e32_rom headers (physfirst=0x{physfirst:08X}) ...')
    mods = scan_e32_modules_direct(img, physfirst)
    log(f'  Found {len(mods)} e32_rom module candidates')
    if not mods:
        return []

    win_dir = out_dir / 'Windows'
    win_dir.mkdir(parents=True, exist_ok=True)
    used_names = set()
    results    = []
    ok = partial_ok = fail = 0

    for m in mods:
        e32_off = m['e32_off']
        vbase   = m['vbase']
        name    = m['name'] or f'_mod_{e32_off:08X}.bin'

        candidate = name.lower()
        if candidate in used_names:
            base, sep, ext = candidate.rpartition('.')
            candidate = (f'{base}_{e32_off:08x}.{ext}' if sep
                         else f'{candidate}_{e32_off:08x}')
        used_names.add(candidate)
        m['out_filename'] = candidate

        info = extract_module_image(img, physfirst, e32_va=vbase, o32_va=vbase + E32_SIZE)
        m['sections_total']   = info['sections_total']
        m['sections_used']    = info['sections_used']
        m['sections_skipped'] = info.get('sections_skipped', 0)
        m['e32_vsize_bytes']  = info['e32_vsize_bytes']
        m['reason']           = info['reason']

        if info['bytes'] is None:
            fail += 1
            m['extracted'] = False
            log(f'  FAIL  [{e32_off:08X}] {candidate:<40s} {info["reason"]}')
            (win_dir / f'{candidate}.unrecoverable').write_bytes(b'')
            results.append(m)
            continue

        out_path = win_dir / candidate
        if info.get('e32') and info.get('section_data'):
            pe_bytes = build_pe_from_rom_module(
                info['e32'], info['valid_sections'], info['section_data'], cpu_type)
            out_path.write_bytes(pe_bytes)
            m['extracted']      = True
            m['extracted_size'] = len(pe_bytes)
            m['sha256']         = hashlib.sha256(pe_bytes).hexdigest()
        else:
            out_path.write_bytes(info['bytes'])
            m['extracted']      = True
            m['extracted_size'] = len(info['bytes'])
            m['sha256']         = hashlib.sha256(info['bytes']).hexdigest()

        if m['sections_skipped'] > 0:
            m['extraction_type'] = 'partial_pe'
            partial_ok += 1
        else:
            m['extraction_type'] = 'full_pe'
            ok += 1
        log(f'  {"OK  " if not m["sections_skipped"] else "PART"} '
            f'[{e32_off:08X}] {candidate:<40s} '
            f'{m["extracted_size"]:8,}B  {m["objcnt"]}sec')
        results.append(m)

    log(f'  {ok} full + {partial_ok} partial + {fail} failed  ({len(mods)} candidates)')
    return results


def carve_pe_files(img, pe_list, out_dir, meta_dir):
    win_dir   = out_dir / '_Carved'
    win_dir.mkdir(parents=True, exist_ok=True)
    img_len   = len(img)
    carved    = 0
    used_names = set()
    for p in pe_list:
        off  = p['offset']
        sz   = min(p['raw_size'], img_len - off)
        if sz < 64:
            continue
        fname = p.get('name')
        if fname:
            fname_lower = fname.lower()
        elif p['is_dll']:
            fname_lower = f'_unknown_dll_{off:08x}.dll'
        else:
            fname_lower = f'_unknown_exe_{off:08x}.exe'
        if fname_lower in used_names:
            base, ext = fname_lower.rsplit('.', 1) if '.' in fname_lower else (fname_lower, 'bin')
            fname_lower = f'{base}_{off:08x}.{ext}'
        used_names.add(fname_lower)
        p['out_filename'] = fname_lower
        pe_bytes = bytes(img[off:off+sz])
        (win_dir / fname_lower).write_bytes(pe_bytes)
        p['sha256']         = hashlib.sha256(pe_bytes).hexdigest()
        p['extracted_size'] = sz
        carved += 1
        mach = _PE_MACHINE_NAMES.get(p['machine'], f"0x{p['machine']:04X}")
        kind = 'DLL' if p['is_dll'] else 'EXE'
        log(f'  CARVED: {fname_lower:<35s} {sz:8,}B  {mach} {kind}  @ 0x{off:08X}')
    log(f'{carved}/{len(pe_list)} PE files carved to {win_dir}')
    return carved


def parse_mod_tocentry(img, off, physfirst):
    if off + TOCENTRY_SIZE > len(img):
        return None
    name_va = struct.unpack_from('<I', img, off + 0x10)[0]
    noff    = va2off(name_va, physfirst)
    return dict(
        index        = -1,
        tocentry_off = off,
        attrs        = struct.unpack_from('<I', img, off + 0x00)[0],
        fsize        = struct.unpack_from('<I', img, off + 0x0C)[0],
        name_va      = name_va,
        e32_va       = struct.unpack_from('<I', img, off + 0x14)[0],
        o32_va       = struct.unpack_from('<I', img, off + 0x18)[0],
        load_va      = struct.unpack_from('<I', img, off + 0x1C)[0],
        name_off     = noff,
        name         = read_cstring(img, noff) if noff is not None else None,
    )


def parse_file_tocentry(img, off, physfirst):
    if off + FILESENTRY_SIZE > len(img):
        return None
    slot = bytes(img[off:off + FILESENTRY_SIZE])
    if slot == bytes(FILESENTRY_SIZE) or slot == bytes([0xFF] * FILESENTRY_SIZE):
        return None
    name_va = struct.unpack_from('<I', img, off + 0x14)[0]
    data_va = struct.unpack_from('<I', img, off + 0x18)[0]
    noff    = va2off(name_va, physfirst)
    doff    = va2off(data_va, physfirst)
    return dict(
        index        = -1,
        tocentry_off = off,
        attrs        = struct.unpack_from('<I', img, off + 0x00)[0],
        fsize        = struct.unpack_from('<I', img, off + 0x0C)[0],
        comp_size    = struct.unpack_from('<I', img, off + 0x10)[0],
        name_va      = name_va,
        data_va      = data_va,
        name_off     = noff,
        data_off     = doff,
        name         = read_cstring(img, noff) if noff is not None else None,
    )


def write_sha256sums(out_dir, meta_dir):
    entries = []
    for fpath in sorted(out_dir.rglob('*')):
        if not fpath.is_file():
            continue
        try:
            rel = fpath.relative_to(out_dir)
        except ValueError:
            continue
        if str(rel).startswith('_meta'):
            continue
        h = hashlib.sha256(fpath.read_bytes()).hexdigest()
        entries.append(f'{h} *{rel.as_posix()}')
    sums_path = meta_dir / 'sha256sums.txt'
    sums_path.write_text('\n'.join(entries) + '\n', encoding='utf-8')
    return len(entries)

# ---------------------------------------------------------------------------
# Partition format detection (non-ROMHDR partitions)
# ---------------------------------------------------------------------------

def _avr_ivt_score(data):
    """Count leading 0C94-pattern words (AVR JMP opcode, little-endian 940C)."""
    count = 0
    for i in range(0, min(128, len(data) - 1), 4):
        if data[i] == 0x0C and data[i+1] == 0x94:
            count += 1
    return count

def _parse_ti_ch(data):
    """Check for TI OMAP4 Configuration Header (CHSETTINGS at offset 0x14)."""
    if len(data) < 0x30:
        return None
    tag = data[0x14:0x14+10]
    if tag == b'CHSETTINGS':
        return {'format': 'TI_CH_OMAP4', 'tag': 'CHSETTINGS', 'offset': 0x14}
    return None

def _parse_bmp(data):
    """Check for BMP splash screen — standard BMP magic with plausible CE display dimensions."""
    import struct as _s
    if len(data) < 54 or data[:2] != b'BM':
        return None
    fsize  = _s.unpack_from('<I', data, 2)[0]
    px_off = _s.unpack_from('<I', data, 10)[0]
    if _s.unpack_from('<I', data, 14)[0] != 40:  # BITMAPINFOHEADER size
        return None
    width  = _s.unpack_from('<I', data, 18)[0]
    height = _s.unpack_from('<I', data, 22)[0]
    bpp    = _s.unpack_from('<H', data, 28)[0]
    return {'format': 'BMP', 'width': width, 'height': height, 'bpp': bpp,
            'file_size': fsize, 'pixel_offset': px_off}

def _parse_arm_blob(data):
    """Check for ARM bare-metal image — ARM B or LDR PC at reset vector (offset 0)."""
    import struct as _s
    if len(data) < 4:
        return None
    w = _s.unpack_from('<I', data, 0)[0]
    if (w & 0xFF000000) == 0xEA000000:
        offset = w & 0x00FFFFFF
        if offset & 0x800000:
            offset |= 0xFF000000
        import ctypes
        offset = ctypes.c_int32(offset).value
        target = 0 + 8 + (offset << 2)
        return {'format': 'ARM_BLOB', 'reset_vector': 'B', 'target': target}
    if w == 0xE59FF018:
        return {'format': 'ARM_BLOB', 'reset_vector': 'LDR_PC', 'target': None}
    return None

def _parse_partition_table(data):
    """Extract partition names from the Symbol PT partition table blob."""
    names = []
    i = 0
    while i < len(data):
        if 32 <= data[i] < 127:
            end = data.find(b'\x00', i)
            if end != -1 and 4 <= end - i <= 40:
                s = data[i:end].decode('ascii', errors='replace')
                if s.isprintable() and len(s) >= 4:
                    names.append(s)
                    i = end + 1
                    continue
        i += 1
    return names if len(names) >= 5 else None

def detect_partition_format(img, partition_id, out_dir, meta_dir):
    """
    Identify and extract non-ROMHDR partition formats.
    Called from the no-ROMHDR fallback path.
    Saves named artifacts to out_dir and metadata to meta_dir.
    Returns a dict describing what was found.
    """
    result = {'partition_id': partition_id, 'detected_format': 'unknown', 'artifacts': []}

    # --- BMP splash screen ---
    bmp = _parse_bmp(img)
    if bmp:
        result['detected_format'] = 'BMP_SPLASH'
        result['bmp'] = bmp
        out_path = out_dir / 'splash.bmp'
        out_path.write_bytes(img[:bmp['file_size']] if bmp['file_size'] <= len(img) else img)
        result['artifacts'].append(str(out_path))
        log(f'\n=== Partition Format: BMP Splash Screen ===')
        log(f'  {bmp["width"]}x{bmp["height"]} px, {bmp["bpp"]}-bpp')
        log(f'  Saved: splash.bmp')
        return result

    # --- TI OMAP4 Configuration Header (bootloader) ---
    ch = _parse_ti_ch(img)
    if ch:
        result['detected_format'] = 'TI_OMAP4_BOOTLOADER'
        result['ti_ch'] = ch
        # scan for embedded strings of interest
        strs = []
        i = 0
        while i < len(img) - 1:
            if img[i+1] == 0 and 32 <= img[i] < 127:
                j = i; chars = []
                while j+1 < len(img) and img[j+1] == 0 and 32 <= img[j] < 127:
                    chars.append(chr(img[j])); j += 2
                s = ''.join(chars)
                if len(s) >= 6: strs.append(s)
                i = j
            else:
                i += 1
        pdb_names = [s for s in strs if s.endswith('.pdb')]
        exe_names = [s for s in strs if s.endswith('.exe')]
        result['unicode_strings'] = strs[:40]
        result['pdb_refs'] = pdb_names
        result['exe_refs'] = exe_names
        raw_path = out_dir / 'bootloader.bin'
        raw_path.write_bytes(bytes(img))
        result['artifacts'].append(str(raw_path))
        log(f'\n=== Partition Format: TI OMAP4 Bootloader (CH header) ===')
        log(f'  CHSETTINGS tag at offset 0x14')
        for s in pdb_names: log(f'  PDB ref: {s}')
        for s in exe_names: log(f'  EXE ref: {s}')
        log(f'  Saved: bootloader.bin')
        return result

    # --- AVR firmware (External Agent dock MCU) ---
    avr_score = _avr_ivt_score(img)
    if avr_score >= 4 or partition_id == 0x1A:
        result['detected_format'] = 'AVR_FIRMWARE'
        result['avr_ivt_vectors'] = avr_score
        # extract ASCII strings for diagnostic
        strs = []
        cur = []
        for b in img:
            if 32 <= b < 127: cur.append(chr(b))
            else:
                if len(cur) >= 6: strs.append(''.join(cur))
                cur = []
        version_strs = [s for s in strs if any(x in s for x in ['Ver','ver','MPA','EA'])]
        result['ascii_strings'] = strs[:60]
        result['version_hints'] = version_strs
        raw_path = out_dir / 'ea_avr_firmware.bin'
        raw_path.write_bytes(bytes(img))
        result['artifacts'].append(str(raw_path))
        log(f'\n=== Partition Format: AVR Firmware (External Agent dock MCU) ===')
        log(f'  AVR JMP IVT vectors detected: {avr_score} in first 128 bytes')
        for s in version_strs[:5]: log(f'  Version hint: {repr(s)}')
        # emit IVT table
        log(f'  Interrupt Vector Table (first 16 entries):')
        import struct as _s
        for idx in range(min(16, len(img)//4)):
            w = _s.unpack_from('<H', img, idx*4)[0]
            w2 = _s.unpack_from('<H', img, idx*4+2)[0]
            target = (w2 << 16 | w) if False else None
            if img[idx*4] == 0x0C and img[idx*4+1] == 0x94:
                dest = _s.unpack_from('<H', img, idx*4+2)[0] * 2
                log(f'    [{idx:2d}] JMP 0x{dest:04x}')
            else:
                raw = ' '.join(f'{img[idx*4+k]:02x}' for k in range(4))
                log(f'    [{idx:2d}] {raw}')
        log(f'  Saved: ea_avr_firmware.bin')
        return result

    # --- ARM bare-metal monitor/firmware ---
    arm = _parse_arm_blob(img)
    if arm:
        result['detected_format'] = 'ARM_BARE_METAL'
        result['arm'] = arm
        # full string extraction (unicode + ascii)
        strs_u = []
        i = 0
        while i < len(img) - 1:
            if img[i+1] == 0 and 32 <= img[i] < 127:
                j = i; chars = []
                while j+1 < len(img) and img[j+1] == 0 and 32 <= img[j] < 127:
                    chars.append(chr(img[j])); j += 2
                s = ''.join(chars)
                if len(s) >= 6: strs_u.append(s)
                i = j
            else:
                i += 1
        strs_a = []
        cur = []
        for b in img:
            if 32 <= b < 127: cur.append(chr(b))
            else:
                if len(cur) >= 8: strs_a.append(''.join(cur))
                cur = []
        soc_hints = [s for s in strs_a + strs_u if any(x in s for x in ['OMAP','omap','ARM','cpu','CPU','MHz','GHz'])]
        cmd_hints = [s for s in strs_a + strs_u if any(x in s for x in ['menu','command','available','monitor','help','?'])]
        err_hints = [s for s in strs_a + strs_u if any(x in s.lower() for x in ['error','fail','exception','handler'])]
        result['unicode_strings'] = strs_u[:60]
        result['ascii_strings']   = strs_a[:60]
        result['soc_hints']       = soc_hints
        result['cmd_hints']       = cmd_hints
        result['err_hints']       = err_hints
        raw_path  = out_dir / 'arm_monitor.bin'
        raw_path.write_bytes(bytes(img))
        result['artifacts'].append(str(raw_path))
        log(f'\n=== Partition Format: ARM Bare-Metal Firmware ===')
        if arm['reset_vector'] == 'B':
            log(f'  Reset vector: B 0x{arm["target"]:08x}')
        else:
            log(f'  Reset vector: LDR PC,[PC,#0x18]')
        for s in soc_hints[:5]:  log(f'  SoC hint: {repr(s)}')
        for s in cmd_hints[:5]:  log(f'  Monitor cmd hint: {repr(s)}')
        for s in err_hints[:3]:  log(f'  Error handler hint: {repr(s)}')
        log(f'  Unicode strings ({len(strs_u)}):')
        for s in strs_u[:20]:   log(f'    {repr(s)}')
        log(f'  ASCII strings ({len(strs_a)}):')
        for s in strs_a[:20]:   log(f'    {repr(s)}')
        log(f'  Saved: arm_monitor.bin')
        return result

    # --- Partition Table descriptor ---
    if len(img) < 4096:
        names = _parse_partition_table(img)
        if names:
            result['detected_format'] = 'PARTITION_TABLE'
            result['partition_names'] = names
            pt_path = out_dir / 'partition_table.json'
            pt_path.write_text(json.dumps({'partitions': names}, indent=2))
            result['artifacts'].append(str(pt_path))
            log(f'\n=== Partition Format: Symbol Partition Table ===')
            for i, n in enumerate(names):
                log(f'  [{i:2d}] {n}')
            log(f'  Saved: partition_table.json')
            return result

    result['detected_format'] = 'RAW_BLOB'
    log(f'\n=== Partition Format: Raw blob (unrecognized) ===')
    log(f'  partition_id=0x{partition_id:02X}  size={len(img):,} bytes')
    log(f'  magic: {bytes(img[:4]).hex()}')
    return result


# ---------------------------------------------------------------------------
# APF container parser
# ---------------------------------------------------------------------------

def parse_apf(apf_path, out_dir, meta_dir):
    """
    Parse a Symbol/Zebra APF (Application Package File) container.

    APF header layout (all strings null-terminated ASCII):
      [0x00] u8  0x00
      [0x01] u8  0x02  (format marker)
      [0x02] str package_name\x00
      [N]    str version\x00
      [M]    ...command_line\x00
      [P]    str file_count_str\x00  (ASCII decimal + space + "0 SYMBOL")
      File entries follow, each:
        u16  flags/type
        str  destination_path\x00  (e.g. \\windows\\foo.dll)
        str  file_size_decimal\x00 (ASCII decimal)
        u8[] padding to alignment
        u8[] file_data[file_size]

    Returns list of extracted file dicts.
    """
    data = Path(apf_path).read_bytes()
    files = []
    manifest = {}

    log(f'\n=== APF Container Parse ===')
    log(f'  File: {apf_path}')
    log(f'  Size: {len(data):,} bytes')

    # --- parse header fields ---
    if len(data) < 4 or data[0] != 0x00 or data[1] != 0x02:
        log('  ERROR: Not a valid APF file (bad magic)')
        return files

    pos = 2
    def read_cstr_pos(d, p):
        end = d.find(b'\x00', p)
        if end == -1: return '', p
        return d[p:end].decode('ascii', errors='replace'), end + 1

    pkg_name, pos = read_cstr_pos(data, pos)
    version,  pos = read_cstr_pos(data, pos)
    cmd_line, pos = read_cstr_pos(data, pos)
    count_str,pos = read_cstr_pos(data, pos)
    vendor,   pos = read_cstr_pos(data, pos)

    manifest['package_name'] = pkg_name
    manifest['version']      = version
    manifest['command_line'] = cmd_line
    manifest['count_field']  = count_str
    manifest['vendor']       = vendor

    log(f'  Package: {pkg_name}')
    log(f'  Version: {version}')
    log(f'  Command: {cmd_line}')
    log(f'  Count:   {count_str}')
    log(f'  Vendor:  {vendor}')

    # align pos to next 2-byte boundary for file entries
    if pos % 2: pos += 1

    entry_idx = 0
    while pos < len(data) - 4:
        # skip null padding between entries
        while pos < len(data) and data[pos] == 0x00:
            pos += 1
        if pos >= len(data) - 4:
            break

        # file entry: flags(2) + path\0 + size_decimal\0 + [padding] + data
        flags = (data[pos] << 8) | data[pos+1]
        pos += 2

        if pos >= len(data):
            break

        dest_path, pos = read_cstr_pos(data, pos)
        if not dest_path:
            break

        # skip padding nulls before size field
        while pos < len(data) and data[pos] == 0x00:
            pos += 1

        size_str, pos = read_cstr_pos(data, pos)
        size_str = size_str.strip()
        if not size_str.isdigit():
            # try to recover — scan forward for next plausible entry
            log(f'  WARN: entry {entry_idx}: bad size field {repr(size_str)}, skipping')
            break

        file_size = int(size_str)

        # skip padding nulls before file data
        while pos < len(data) and data[pos] == 0x00:
            pos += 1

        if pos + file_size > len(data):
            log(f'  WARN: entry {entry_idx}: {dest_path} claims {file_size} bytes but only {len(data)-pos} remain')
            file_size = len(data) - pos

        file_data = data[pos:pos+file_size]
        pos += file_size

        # determine output name from dest_path
        fname = dest_path.replace('\\', '/').lstrip('/').split('/')[-1]
        if not fname:
            fname = f'apf_file_{entry_idx:03d}.bin'

        out_path = out_dir / fname
        out_path.write_bytes(file_data)

        magic = file_data[:4].hex() if len(file_data) >= 4 else '----'
        log(f'  [{entry_idx:2d}] {dest_path:<40} {file_size:>10,} bytes  magic={magic}  -> {fname}')

        finfo = {
            'index':      entry_idx,
            'dest_path':  dest_path,
            'file_name':  fname,
            'file_size':  file_size,
            'flags':      flags,
            'magic':      magic,
            'extracted':  str(out_path),
        }
        files.append(finfo)
        entry_idx += 1

        # if this is a .bgz file, flag it in the manifest for the caller
        if fname.lower().endswith('.bgz'):
            finfo['is_bgz'] = True
            log(f'       ^^^ BGZ image — can be passed to HEXtractor2 BGZ pipeline')
        elif magic.startswith('4d5a') or magic.startswith('4d 5a'):
            finfo['is_pe'] = True

    manifest['files'] = files
    (meta_dir / 'apf_manifest.json').write_text(json.dumps(manifest, indent=2, default=str))
    log(f'\n  {entry_idx} files extracted')
    log(f'  Saved: _meta/apf_manifest.json')
    return files


# ---------------------------------------------------------------------------
# Compressed HEX record detection
# ---------------------------------------------------------------------------

def check_compressed_hex_records(hex_path):
    """
    Scan a Symbol HEX file for record types other than 82/84/02/A0/A1/A3/01.
    Unknown types may indicate zlib-compressed records (DecodeCompressedRecord
    path in FlashUpdateUtility).  Returns list of (offset, record_type, byte_count).
    """
    data = Path(hex_path).read_bytes()
    unknown = []
    pos = 0
    known_types = {'82', '84', '02', 'A0', 'A1', 'A3', '01', '00'}
    while pos < len(data):
        while pos < len(data) and data[pos:pos+1] != b':':
            pos += 1
        if pos >= len(data): break
        pos += 1
        if pos + 8 > len(data): break
        hdr = data[pos:pos+8].decode('ascii', errors='replace')
        try:
            bc = int(hdr[0:2], 16)
            rt = hdr[6:8].upper()
        except Exception:
            pos += 1; continue
        pos += 8
        if rt not in known_types:
            unknown.append({'offset': pos - 9, 'type': rt, 'bc': bc})
        pos += bc * 2 + 2
        while pos < len(data) and data[pos:pos+1] in (b'\r', b'\n'):
            pos += 1
    return unknown


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global LOG_PATH, _BGZ_IMAGE_START

    parser = argparse.ArgumentParser(
        description='Unified OS partition extractor for Symbol HEX and BGZ images')
    parser.add_argument('--input', required=True,
                        help='Source image: .hex (Symbol HEX), .bgz (gzip NK.bin), or .apf (APF container)')
    parser.add_argument('--out', default=None,
                        help='Output directory (default: extract/<input-stem>/)')
    parser.add_argument('--physfirst', default=None,
                        help='Override physfirst VA (hex, e.g. 0x81168000). '
                             'BGZ: auto-detected from ECECT when not specified.')
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.is_absolute():
        input_path = input_path.resolve()

    out_dir = Path(args.out) if args.out else Path('extract') / input_path.stem

    if out_dir.exists() and any(out_dir.iterdir()):
        sys.stderr.write(
            f'FATAL: extract dir exists and is not empty: {out_dir}\n'
            f'Remove it and re-run.\n')
        sys.exit(2)

    meta_dir = out_dir / '_meta'
    meta_dir.mkdir(parents=True, exist_ok=True)
    LOG_PATH = out_dir / 'unpack.log'

    suffix = input_path.suffix.lower()
    if suffix == '.bgz':
        fmt = 'bgz'
    elif suffix == '.apf':
        fmt = 'apf'
    else:
        fmt = 'hex'

    log('=== HEXtractor2.py ===')
    log(f'Input  : {input_path}  [{fmt.upper()}]')
    log(f'Output : {out_dir}')

    if not input_path.exists():
        log(f'FATAL: input not found: {input_path}')
        save_log(); sys.exit(1)

    # ------------------------------------------------------------------
    # Stage 1: load flat image
    # ------------------------------------------------------------------
    physfirst_override = int(args.physfirst, 16) if args.physfirst else None

    # ------------------------------------------------------------------
    # APF: extract container, then exit (sub-images can be re-run separately)
    # ------------------------------------------------------------------
    if fmt == 'apf':
        log('\n=== Stage 1: APF container extraction ===')
        extracted = parse_apf(input_path, out_dir, meta_dir)
        bgz_files = [f for f in extracted if f.get('is_bgz')]
        pe_files  = [f for f in extracted if f.get('is_pe')]
        log(f'\n=== APF extraction complete ===')
        log(f'  {len(extracted)} files extracted')
        if bgz_files:
            log(f'  BGZ images found — re-run HEXtractor2 on each to extract OS modules:')
            for f in bgz_files:
                log(f'    {out_dir / f["file_name"]}')
        if pe_files:
            log(f'  PE files carved:')
            for f in pe_files:
                log(f'    {f["file_name"]}  ({f["file_size"]:,} bytes)')
        save_log()
        return 0

    if fmt == 'bgz':
        _BGZ_IMAGE_START = None
        log('\n=== Stage 1: BGZ decompression + NK.bin bootstrap + OS flat extraction ===')
        flat, nk_image_start, nk_image_length, nk_nrecords, nk_end_off, ecect_physfirst = \
            load_flat_from_bgz(input_path)
        partition_size = len(flat)
        img            = bytearray(flat)
        hex_meta = dict(
            input_format          = 'bgz',
            partition_id          = None,
            partition_size        = partition_size,
            device_target         = None,
            has_a1                = False,
            has_a3                = False,
            a3_values             = [],
            first_a3_has_type02   = False,
            segment_step          = None,
            records_per_segment   = None,
            segments_per_a3       = None,
            record_block_size     = None,
            nk_image_start        = nk_image_start,
            nk_image_length       = nk_image_length,
            nk_nrecords           = nk_nrecords,
            nk_bootstrap_end_off  = nk_end_off,
            ecect_physfirst       = ecect_physfirst,
        )
        packed_bin   = b''
        addrmap_text = ''
        _physfirst_bgz = physfirst_override or ecect_physfirst
        if _physfirst_bgz:
            log(f'OS flat image: {len(img):,} bytes  physfirst=0x{_physfirst_bgz:08X}')
        else:
            log(f'OS flat image: {len(img):,} bytes (base VA determined by ROMHDR scan)')

    else:
        _BGZ_IMAGE_START  = None
        ecect_physfirst   = None
        log('\n=== Stage 1: Symbol HEX header scan (A0/A1/A3) ===')
        hex_meta = scan_hex_header(input_path)
        hex_meta['input_format'] = 'hex'
        partition_size = hex_meta['partition_size']
        if partition_size is None:
            log('FATAL: no A0 record found — not a Symbol HEX file')
            save_log(); sys.exit(1)
        log(f'partition_id   = 0x{hex_meta["partition_id"]:02X}')
        log(f'partition_size = {partition_size:,} bytes')
        log(f'device_target  = {hex_meta["device_target"]}')
        save_log()

        # Check for unknown/compressed HEX record types before parsing
        unknown_recs = check_compressed_hex_records(input_path)
        if unknown_recs:
            log(f'  WARN: {len(unknown_recs)} unknown record type(s) — may be zlib-compressed:')
            for r in unknown_recs[:10]:
                log(f'    offset=0x{r["offset"]:x}  type={r["type"]}  bc={r["bc"]}')

        log('\n=== Stage 1b: HEX to flat image ===')
        flat, packed_bin, addrmap_text = load_flat_from_hex(input_path, partition_size)
        img = bytearray(flat)
        log(f'Flat image: {len(img):,} bytes')

    # Save base image and HEX-path artifacts
    base_bin = meta_dir / 'base_image.bin'
    base_bin.write_bytes(img)
    log(f'Saved: _meta/base_image.bin ({len(img):,} bytes)')
    if packed_bin:
        (meta_dir / f'{input_path.stem}.bin').write_bytes(packed_bin)
        (meta_dir / f'{input_path.stem}.adrmap').write_text(addrmap_text, encoding='ascii')
    save_log()

    # ------------------------------------------------------------------
    # Stage 2: ROMHDR scan (format-agnostic)
    # ------------------------------------------------------------------
    log('\n=== Stage 2: ROMHDR scan ===')
    # BGZ RAMIMAGE: ROMHDR is runtime-only (not stored in flat).
    # physfirst_override (--physfirst CLI) or ecect_physfirst (from NK.bin bootstrap ECECT)
    # are used as fallback if the scan finds nothing.
    _known_physfirst = physfirst_override or (ecect_physfirst if fmt == 'bgz' else None)
    if _known_physfirst:
        log(f'Known physfirst = 0x{_known_physfirst:08X} '
            f'({"CLI override" if physfirst_override else "ECECT derivation"})')

    romhdr     = None
    romhdr_off = None
    for off in range(0, len(img) - ROMHDR_SIZE, 4):
        cpu = struct.unpack_from('<H', img, off + 0x44)[0]
        if cpu not in (0x01C0, 0x01C2, 0x01C4):
            continue
        nummods_c  = struct.unpack_from('<I', img, off + 0x10)[0]
        numfiles_c = struct.unpack_from('<I', img, off + 0x30)[0]
        if not (10 < nummods_c < 1000 and 10 < numfiles_c < 5000):
            continue
        candidate = parse_romhdr(img, off)
        if candidate['physfirst'] < 0x10000000:
            continue
        if candidate['physlast'] <= candidate['physfirst']:
            continue
        toc_cand = off + ROMHDR_SIZE
        if toc_cand + 5 * TOCENTRY_SIZE > len(img):
            continue
        good_names = 0
        for _i in range(min(5, nummods_c)):
            _eo  = toc_cand + _i * TOCENTRY_SIZE
            _nva = struct.unpack_from('<I', img, _eo + 0x10)[0]
            _nfo = va2off(_nva, candidate['physfirst'])
            _n   = read_cstring(img, _nfo)
            if _n and '.' in _n:
                good_names += 1
        if good_names < 3:
            continue
        romhdr     = candidate
        romhdr_off = off
        log(f'ROMHDR found at flat offset 0x{off:08X}')
        if _BGZ_IMAGE_START is not None and romhdr['physfirst'] != _BGZ_IMAGE_START:
            log(f'NOTE: physfirst=0x{romhdr["physfirst"]:08X} '
                f'differs from NK ImageStart=0x{_BGZ_IMAGE_START:08X} '
                f'(delta=0x{romhdr["physfirst"] - _BGZ_IMAGE_START:08X})')
        break

    if romhdr is None:
        if _known_physfirst:
            log(f'ROMHDR not found (CE7 RAMIMAGE — runtime-only). '
                f'physfirst=0x{_known_physfirst:08X} from ECECT/override.')
        else:
            log('ROMHDR not found — falling through to PE/FlashFX scan')
        save_log()

        flashfx_offsets = detect_flashfx(img)
        if flashfx_offsets:
            log(f'\n=== FlashFX 3.00 filesystem ===')
            for foff in flashfx_offsets[:10]:
                log(f'  block at 0x{foff:08X}')
            if len(flashfx_offsets) > 10:
                log(f'  ... and {len(flashfx_offsets)-10} more')

        e32_modules = []
        if _known_physfirst:
            log(f'\n=== CE7 RAMIMAGE: direct e32_rom module extraction ===')
            e32_modules = extract_e32_modules_direct(
                img, _known_physfirst, out_dir, meta_dir, cpu_type=0x01C4)
            save_log()

        pe_list = scan_pe_headers(img)
        log(f'\n=== PE scan: {len(pe_list)} executables ===')
        for p in pe_list:
            mach = _PE_MACHINE_NAMES.get(p['machine'], f"0x{p['machine']:04X}")
            kind = 'DLL' if p['is_dll'] else 'EXE'
            log(f'  0x{p["offset"]:08X} | {mach:12s} | {p["num_sections"]}sec | {kind} | '
                f'{p["raw_size"]:8,}B | {p.get("name") or "(unnamed)"}')
        if pe_list:
            carve_pe_files(img, pe_list, out_dir, meta_dir)
        save_log()

        # Stage 2b: partition format detection for non-CE partitions
        partition_id = hex_meta.get('partition_id') if fmt == 'hex' else None
        log(f'\n=== Stage 2b: Partition format detection ===')
        part_fmt = detect_partition_format(img, partition_id or 0xFF, out_dir, meta_dir)
        log(f'  Detected: {part_fmt["detected_format"]}')
        save_log()

        free = find_free_regions(img, min_size=64)
        manifest = dict(
            source_path    = str(input_path),
            input_format   = fmt,
            hex_meta       = hex_meta,
            romhdr_off     = None,
            physfirst      = _known_physfirst,
            flashfx_blocks = len(flashfx_offsets),
            e32_modules    = [{k: v for k, v in m.items() if k not in ('unit',)}
                              for m in e32_modules],
            pe_executables   = [{k: v for k, v in p.items() if k != 'sections'} for p in pe_list],
            free_regions     = [{'offset': o, 'size': s} for o, s in free],
            partition_format = part_fmt,
        )
        (meta_dir / 'manifest.json').write_text(json.dumps(manifest, indent=2, default=str))
        log('\nDone (no ROMHDR).')
        save_log()
        return 0

    physfirst = romhdr['physfirst']
    physlast  = romhdr['physlast']
    nummods   = romhdr['nummods']
    numfiles  = romhdr['numfiles']
    log(f'physfirst = 0x{physfirst:08X}')
    log(f'physlast  = 0x{physlast:08X}')
    log(f'nummods   = {nummods}')
    log(f'numfiles  = {numfiles}')
    log(f'cpu       = 0x{romhdr["cpu"]:04X}  ({_PE_MACHINE_NAMES.get(romhdr["cpu"], "unknown")})')
    save_log()

    # ------------------------------------------------------------------
    # Stage 3: TOC + file table walk
    # ------------------------------------------------------------------
    toc_start        = romhdr_off + ROMHDR_SIZE
    file_table_start = toc_start + nummods * TOCENTRY_SIZE
    file_table_end   = file_table_start + numfiles * FILESENTRY_SIZE
    log(f'\n=== Stage 3: TOC walk ===')
    log(f'toc_start        = 0x{toc_start:08X}')
    log(f'file_table_start = 0x{file_table_start:08X}')
    log(f'file_table_end   = 0x{file_table_end:08X}')
    if file_table_end > len(img):
        log(f'NOTE: file table extends {file_table_end - len(img)} bytes past flat image end')
    save_log()

    log('\n--- Modules ---')
    modules = []
    unnamed = 0
    for i in range(nummods):
        m = parse_mod_tocentry(img, toc_start + i * TOCENTRY_SIZE, physfirst)
        if m is None:
            unnamed += 1
            continue
        m['index'] = i
        modules.append(m)
        if m['name'] is None:
            unnamed += 1
    named_mods = [m for m in modules if m['name']]
    log(f'{len(named_mods)} named modules, {unnamed} unnamed/truncated')

    log('\n--- File table ---')
    files = []
    errs  = 0
    for i in range(numfiles):
        off = file_table_start + i * FILESENTRY_SIZE
        if off + FILESENTRY_SIZE > len(img):
            log(f'  file[{i}]: offset past flat image')
            continue
        f = parse_file_tocentry(img, off, physfirst)
        if f is None:
            log(f'  file[{i}]: empty slot')
            continue
        f['index'] = i
        files.append(f)
        fat_ok  = validate_fat83_path(f['name']) if f['name'] else False
        warn    = '' if fat_ok else ' [WARN:non-8.3]'
        log(f'  [{i:3d}] {(f["name"] or "?"):<40s} size={f["fsize"]:6d}  '
            f'data_va=0x{f["data_va"]:08X}{warn}')
        if f['name'] and f['data_off'] is not None and f['fsize'] > 0:
            parts    = f['name'].lstrip('\\').split('\\')
            out_path = (out_dir / 'Windows' / parts[0]) if len(parts) == 1 \
                       else (out_dir / Path(*parts))
            out_path.parent.mkdir(parents=True, exist_ok=True)
            dend = f['data_off'] + f['fsize']
            if dend <= len(img):
                file_bytes     = img[f['data_off']:dend]
                out_path.write_bytes(file_bytes)
                f['sha256']    = hashlib.sha256(file_bytes).hexdigest()
            else:
                log(f'    ERR: data past image end')
                errs += 1
    log(f'{len(files)} file entries ({errs} errors)')
    save_log()

    # ------------------------------------------------------------------
    # Stage 4: module extraction
    # ------------------------------------------------------------------
    log('\n=== Stage 4: Module extraction ===')
    modules_dir = out_dir / 'Windows'
    modules_dir.mkdir(parents=True, exist_ok=True)
    blobs_dir   = meta_dir / 'compressed_modules'
    mod_ok = mod_partial = mod_fail = mod_unnamed = 0
    used_names = set()

    for m in modules:
        if m['name'] is None:
            e32_chk = va2off(m['e32_va'], physfirst)
            if e32_chk is None or e32_chk + E32_SIZE > len(img):
                mod_unnamed += 1
                m.update(extracted=False, reason='unnamed_no_e32',
                         e32_flat_offset=None, flat_byte_range=None,
                         sha256_original=None, extraction_type='unnamed_no_e32')
                stub = modules_dir / f'_unrecoverable_idx{m["index"]:03d}.unrecoverable'
                stub.write_bytes(b'')
                continue
            m['name'] = f'_unnamed_mod_{m["index"]:03d}.bin'

        info = extract_module_image(img, physfirst, m['e32_va'], m['o32_va'],
                                    load_va=m.get('load_va', 0))
        m['sections_total']   = info['sections_total']
        m['sections_used']    = info['sections_used']
        m['sections_skipped'] = info['sections_skipped']
        m['e32_vsize_bytes']  = info['e32_vsize_bytes']
        m['reason']           = info['reason']

        e32_off   = va2off(m['e32_va'], physfirst)
        save_blob = e32_off is not None and m['fsize'] > 0 and \
                    e32_off + m['fsize'] <= len(img) and \
                    (info['sections_skipped'] > 0 or info['bytes'] is None)
        if save_blob:
            blobs_dir.mkdir(parents=True, exist_ok=True)
            blob_path = blobs_dir / f'{m["name"].lower()}.blob'
            blob_path.write_bytes(bytes(img[e32_off:e32_off + m['fsize']]))
            m['blob_path']       = str(blob_path.relative_to(out_dir))
            m['blob_size_bytes'] = m['fsize']

        _e32_rt = va2off(m['e32_va'], physfirst)
        if _e32_rt is not None and m['fsize'] > 0 and _e32_rt + m['fsize'] <= len(img):
            m['e32_flat_offset']  = _e32_rt
            m['flat_byte_range']  = [_e32_rt, _e32_rt + m['fsize']]
            m['sha256_original']  = hashlib.sha256(bytes(img[_e32_rt:_e32_rt+m['fsize']])).hexdigest()
        else:
            m['e32_flat_offset'] = m['flat_byte_range'] = m['sha256_original'] = None

        base_lower = m['name'].lower()
        candidate  = base_lower
        if candidate in used_names:
            candidate = f'{base_lower}.idx{m["index"]:03d}'
        used_names.add(candidate)
        m['out_filename'] = candidate

        if info['bytes'] is None:
            if save_blob:
                blob_in_win = modules_dir / f'{candidate}.blob'
                blob_in_win.write_bytes(bytes(img[e32_off:e32_off + m['fsize']]))
                m['extracted_size']  = m['fsize']
                m['sha256']          = hashlib.sha256(bytes(img[e32_off:e32_off+m['fsize']])).hexdigest()
                m['extraction_type'] = 'lzx_blob'
            else:
                (modules_dir / f'{candidate}.unrecoverable').write_bytes(b'')
                m['extraction_type'] = 'unresolvable_va'
            mod_fail += 1
            m['extracted'] = False
            log(f'  FAIL: {m["name"]:<30s} {info["reason"]}')
            continue

        out_path = modules_dir / candidate
        if info.get('e32') and info.get('section_data'):
            pe_bytes = build_pe_from_rom_module(
                info['e32'], info['valid_sections'], info['section_data'], romhdr['cpu'])
            out_path.write_bytes(pe_bytes)
            m['extracted']      = True
            m['extracted_size'] = len(pe_bytes)
            m['sha256']         = hashlib.sha256(pe_bytes).hexdigest()
        else:
            out_path.write_bytes(info['bytes'])
            m['extracted']      = True
            m['extracted_size'] = len(info['bytes'])
            m['sha256']         = hashlib.sha256(info['bytes']).hexdigest()

        if info['sections_skipped'] > 0:
            m['extraction_type'] = 'partial_pe'
            mod_partial += 1
        else:
            m['extraction_type'] = 'full_pe'
            mod_ok += 1

    log(f'{mod_ok} full + {mod_partial} partial + {mod_fail} failed + '
        f'{mod_unnamed} unnamed  (total {mod_ok+mod_partial+mod_fail+mod_unnamed}/{len(modules)})')
    save_log()

    # ------------------------------------------------------------------
    # Stage 5: free regions + manifest
    # ------------------------------------------------------------------
    log('\n=== Stage 5: Free regions ===')
    free       = find_free_regions(img, min_size=64)
    total_free = sum(r[1] for r in free)
    log(f'Total free: {total_free:,} bytes in {len(free)} regions >= 64B')
    for off, sz in free[:15]:
        log(f'  0x{off:010X}  {sz:10,} bytes  ({sz/1024:.1f} KB)')
    save_log()

    manifest = dict(
        source_path         = str(input_path),
        input_format        = fmt,
        hex_meta            = {k: v for k, v in hex_meta.items()
                               if k not in ('partition_id',)},
        partition_id        = hex_meta.get('partition_id'),
        partition_size      = partition_size,
        romhdr_off          = romhdr_off,
        physfirst           = physfirst,
        physlast            = physlast,
        nummods             = nummods,
        numfiles            = numfiles,
        cpu                 = romhdr['cpu'],
        cpu_name            = _PE_MACHINE_NAMES.get(romhdr['cpu'], f'0x{romhdr["cpu"]:04X}'),
        toc_start           = toc_start,
        file_table_start    = file_table_start,
        file_table_end      = file_table_end,
        nk_image_start      = hex_meta.get('nk_image_start'),
        nk_bootstrap_end_off= hex_meta.get('nk_bootstrap_end_off'),
        modules             = [{k: v for k, v in m.items() if k != 'name_off'} for m in modules],
        files               = files,
        free_regions        = [{'offset': o, 'size': s} for o, s in free],
    )
    (meta_dir / 'manifest.json').write_text(json.dumps(manifest, indent=2, default=str))
    nwritten = write_sha256sums(out_dir, meta_dir)
    log(f'Saved: _meta/manifest.json')
    log(f'Saved: _meta/sha256sums.txt ({nwritten} files)')
    log('\nDone.')
    save_log()
    return 0


if __name__ == '__main__':
    sys.exit(main())
