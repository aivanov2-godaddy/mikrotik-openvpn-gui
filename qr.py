"""Small, dependency-free QR encoder for short dashboard share URLs.

The dashboard only needs to encode a short, high-entropy download URL.  A
fixed version-5 QR with low error correction keeps this module compact while
still providing room for the URL and a generous quiet zone in the SVG output.
"""

from __future__ import annotations

import html


_VERSION = 5
_SIZE = 17 + _VERSION * 4
_DATA_CODEWORDS = 108
_ECC_CODEWORDS = 26


def _gf_mul(left: int, right: int) -> int:
    result = 0
    a = left
    b = right
    while b:
        if b & 1:
            result ^= a
        b >>= 1
        a = ((a << 1) ^ 0x11D) if a & 0x80 else (a << 1)
    return result & 0xFF


def _ecc(data: list[int]) -> list[int]:
    generator = [1]
    root = 1
    for _ in range(_ECC_CODEWORDS):
        expanded = [0] * (len(generator) + 1)
        for index, coefficient in enumerate(generator):
            expanded[index] ^= coefficient
            expanded[index + 1] ^= _gf_mul(coefficient, root)
        generator = expanded
        root = _gf_mul(root, 2)

    remainder = data + [0] * _ECC_CODEWORDS
    for index in range(len(data)):
        factor = remainder[index]
        if factor:
            for offset, coefficient in enumerate(generator):
                remainder[index + offset] ^= _gf_mul(coefficient, factor)
    return remainder[-_ECC_CODEWORDS:]


def _data_codewords(value: str) -> list[int]:
    payload = value.encode("utf-8")
    if len(payload) > 100:
        raise ValueError("QR share URL is too long")
    bits = [0, 1, 0, 0]  # byte mode
    bits.extend((len(payload) >> shift) & 1 for shift in range(7, -1, -1))
    for byte in payload:
        bits.extend((byte >> shift) & 1 for shift in range(7, -1, -1))
    capacity = _DATA_CODEWORDS * 8
    bits.extend([0] * min(4, capacity - len(bits)))
    bits.extend([0] * ((-len(bits)) % 8))
    words = [sum(bits[index + bit] << (7 - bit) for bit in range(8)) for index in range(0, len(bits), 8)]
    pad = (0xEC, 0x11)
    pad_index = 0
    while len(words) < _DATA_CODEWORDS:
        words.append(pad[pad_index & 1])
        pad_index += 1
    return words


def _format_coordinates() -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    first: list[tuple[int, int]] = []
    second: list[tuple[int, int]] = []
    for index in range(15):
        if index < 6:
            first.append((8, index))
        elif index < 8:
            first.append((8, index + 1))
        else:
            first.append((8, _SIZE - 15 + index))
        if index < 8:
            second.append((_SIZE - index - 1, 8))
        elif index < 9:
            second.append((15 - index, 8))
        else:
            second.append((15 - index - 1, 8))
    return first, second


def _bch_format(value: int) -> int:
    remainder = value << 10
    generator = 0x537
    while remainder.bit_length() >= generator.bit_length():
        remainder ^= generator << (remainder.bit_length() - generator.bit_length())
    return ((value << 10) | remainder) ^ 0x5412


def _base_matrix() -> tuple[list[list[bool]], list[list[bool]]]:
    modules = [[False] * _SIZE for _ in range(_SIZE)]
    function = [[False] * _SIZE for _ in range(_SIZE)]

    def set_function(x: int, y: int, dark: bool) -> None:
        if 0 <= x < _SIZE and 0 <= y < _SIZE:
            modules[y][x] = dark
            function[y][x] = True

    def finder(left: int, top: int) -> None:
        for dy in range(-1, 8):
            for dx in range(-1, 8):
                dark = 0 <= dx <= 6 and 0 <= dy <= 6 and (
                    dx in (0, 6) or dy in (0, 6) or (2 <= dx <= 4 and 2 <= dy <= 4)
                )
                set_function(left + dx, top + dy, dark)

    finder(0, 0)
    finder(_SIZE - 7, 0)
    finder(0, _SIZE - 7)

    for index in range(8, _SIZE - 8):
        if not function[6][index]:
            set_function(index, 6, index % 2 == 0)
        if not function[index][6]:
            set_function(6, index, index % 2 == 0)

    for center_x in (6, 30):
        for center_y in (6, 30):
            if function[center_y][center_x]:
                continue
            for dy in range(-2, 3):
                for dx in range(-2, 3):
                    set_function(center_x + dx, center_y + dy, max(abs(dx), abs(dy)) != 1)

    set_function(8, _SIZE - 8, True)
    first, second = _format_coordinates()
    for x, y in first + second:
        set_function(x, y, False)
    return modules, function


def _mask(mask: int, row: int, column: int) -> bool:
    if mask == 0:
        return (row + column) % 2 == 0
    if mask == 1:
        return row % 2 == 0
    if mask == 2:
        return column % 3 == 0
    if mask == 3:
        return (row + column) % 3 == 0
    if mask == 4:
        return (row // 2 + column // 3) % 2 == 0
    if mask == 5:
        return (row * column) % 2 + (row * column) % 3 == 0
    if mask == 6:
        return ((row * column) % 2 + (row * column) % 3) % 2 == 0
    return ((row * column) % 3 + (row + column) % 2) % 2 == 0


def _draw_data(base: list[list[bool]], function: list[list[bool]], codewords: list[int], mask: int) -> list[list[bool]]:
    modules = [row[:] for row in base]
    bits = [(byte >> shift) & 1 for byte in codewords for shift in range(7, -1, -1)]
    bit_index = 0
    row = _SIZE - 1
    direction = -1
    column = _SIZE - 1
    while column > 0:
        if column == 6:
            column -= 1
        for offset in range(_SIZE):
            current_row = row + direction * offset
            for current_column in (column, column - 1):
                if function[current_row][current_column]:
                    continue
                bit = bits[bit_index] if bit_index < len(bits) else 0
                bit_index += 1
                modules[current_row][current_column] = bool(bit) ^ _mask(mask, current_row, current_column)
        row += direction * (_SIZE - 1)
        direction = -direction
        column -= 2

    format_bits = _bch_format((1 << 3) | mask)  # level L (01), followed by mask
    first, second = _format_coordinates()
    for index, (x, y) in enumerate(first):
        modules[y][x] = bool((format_bits >> index) & 1)
    for index, (x, y) in enumerate(second):
        modules[y][x] = bool((format_bits >> index) & 1)
    return modules


def _penalty(modules: list[list[bool]]) -> int:
    score = 0
    for row in modules:
        run_value = row[0]
        run_length = 1
        for value in row[1:]:
            if value == run_value:
                run_length += 1
            else:
                if run_length >= 5:
                    score += run_length - 2
                run_value = value
                run_length = 1
        if run_length >= 5:
            score += run_length - 2
    for column in range(_SIZE):
        values = [modules[row][column] for row in range(_SIZE)]
        run_value = values[0]
        run_length = 1
        for value in values[1:]:
            if value == run_value:
                run_length += 1
            else:
                if run_length >= 5:
                    score += run_length - 2
                run_value = value
                run_length = 1
        if run_length >= 5:
            score += run_length - 2
    for row in range(_SIZE - 1):
        for column in range(_SIZE - 1):
            square = modules[row][column]
            if modules[row][column + 1] == square and modules[row + 1][column] == square and modules[row + 1][column + 1] == square:
                score += 3
    patterns = ("10111010000", "00001011101")
    for row in modules:
        sequence = "".join("1" if value else "0" for value in row)
        score += sum(40 for pattern in patterns for index in range(len(sequence) - len(pattern) + 1) if sequence.startswith(pattern, index))
    for column in range(_SIZE):
        sequence = "".join("1" if modules[row][column] else "0" for row in range(_SIZE))
        score += sum(40 for pattern in patterns for index in range(len(sequence) - len(pattern) + 1) if sequence.startswith(pattern, index))
    dark = sum(value for row in modules for value in row)
    score += abs(dark * 20 - _SIZE * _SIZE * 10) // (_SIZE * _SIZE) * 10
    return score


def matrix(value: str) -> list[list[bool]]:
    """Return a QR module matrix for a short UTF-8 value."""
    base, function = _base_matrix()
    codewords = _data_codewords(value)
    codewords += _ecc(codewords)
    candidates = [_draw_data(base, function, codewords, mask) for mask in range(8)]
    return min(candidates, key=_penalty)


def svg(value: str) -> str:
    """Render a QR matrix as a self-contained SVG with a quiet zone."""
    modules = matrix(value)
    paths: list[str] = []
    for row, values in enumerate(modules):
        column = 0
        while column < _SIZE:
            if not values[column]:
                column += 1
                continue
            start = column
            while column < _SIZE and values[column]:
                column += 1
            paths.append(f"M{start + 4} {row + 4}h{column - start}v1h-{column - start}z")
    path = "".join(paths)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {_SIZE + 8} {_SIZE + 8}" '
        f'role="img" aria-label="OpenVPN profile download QR code"><rect width="100%" height="100%" fill="#fff"/>'
        f'<path d="{html.escape(path, quote=True)}" fill="#000"/></svg>'
    )
