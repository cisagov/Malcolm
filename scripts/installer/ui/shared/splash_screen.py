#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.


import os
import sys

from scripts.malcolm_utils import clear_screen


UNICODE_GLYPHS = {
    "M": [
        " ██████   ██████",
        "░░██████ ██████ ",
        " ░███░█████░███ ",
        " ░███░░███ ░███ ",
        " ░███ ░░░  ░███ ",
        " ░███      ░███ ",
        " ░███      ░███ ",
        " █████     █████",
        "░░░░░     ░░░░░ ",
    ],
    "A": [
        "      █████     ",
        "    ███░░░███   ",
        "   ███   ░░███  ",
        "  █████████████ ",
        " ░███░░░░░░░███ ",
        " ░███      ░███ ",
        " ░███      ░███ ",
        " █████     █████",
        "░░░░░     ░░░░░ ",
    ],
    "L": [
        " ████           ",
        "░░███           ",
        " ░███           ",
        " ░███           ",
        " ░███           ",
        " ░███           ",
        " ░███           ",
        " ██████████████ ",
        "░░░░░░░░░░░░░░  ",
    ],
    "C": [
        " ██████████████ ",
        "░░███░░░░░░░░░██",
        " ░███        ░░ ",
        " ░███           ",
        " ░███           ",
        " ░███           ",
        " ░███         ██",
        " ██████████████ ",
        "░░░░░░░░░░░░░░  ",
    ],
}

LEFT_WORD = ["M", "A", "L", "C"]
RIGHT_WORD = ["L", "M"]
WHEEL_FRAME_COUNT = 16

HEADER_TEXT = "Welcome To"
FOOTER_TEXT = "Press any key to continue..."


def splash_screen():
    """Render an animated Malcolm splash with a spinning ASCII 'O'."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return

    import threading
    import time

    safe_clear()

    color_ok, Fore, Style = init_color()

    on_char, shadow_char = pick_block_chars()
    gap = 2
    letter_height = len(UNICODE_GLYPHS["M"])

    baked_glyphs = bake_glyphs(on_char, shadow_char)
    left_glyphs = [baked_glyphs[name] for name in LEFT_WORD]
    right_glyphs = [baked_glyphs[name] for name in RIGHT_WORD]

    wheel_frames = build_wheel_frames(letter_height, on_char)

    def assemble_frame(idx: int, colored: bool = True) -> list[str]:
        wheel = wheel_frames[idx % len(wheel_frames)]
        spacer = " " * gap
        lines: list[str] = []
        for row in range(letter_height):
            parts = [glyph[row] for glyph in left_glyphs]
            wheel_segment = wheel[row]
            if colored and color_ok:
                wheel_segment = f"{Fore.YELLOW}{wheel_segment}{Style.RESET_ALL}"
            parts.append(wheel_segment)
            parts.extend(glyph[row] for glyph in right_glyphs)
            lines.append(spacer.join(parts))
        return lines

    header = HEADER_TEXT
    footer = FOOTER_TEXT

    cols = get_term_width()

    preview_lines = assemble_frame(0, colored=False)
    required_width = max(len(header), len(footer), *(len(line) for line in preview_lines))

    if cols < required_width:
        print(
            "We have a fancy splash screen to show you...\n"
            "But it looks like your terminal isn't wide enough. :(\n"
            "Resize your terminal and re-run the installer to see it. :)\n"
            "Or skip this message next time with --skip-splash"
        )
        print(f"\nMinimum width required: {required_width}. Current width: {cols}.\n")
        KeyReader().wait_for_key("Press any key to continue with install... ")
        return

    pad_left = max(0, (cols - len(preview_lines[0])) // 2)
    pad = " " * pad_left

    header_pad = " " * max(0, (cols - len(header)) // 2)
    footer_pad = " " * max(0, (cols - len(footer)) // 2)
    header_gap_lines = 1
    footer_gap_lines = 1

    block_lines = assemble_frame(0, colored=True)
    print(header_pad + header)
    print("\n" * header_gap_lines, end="")
    for line in block_lines:
        print(pad + line)
    print("\n" * footer_gap_lines, end="")
    print(footer_pad + footer)

    stop_event = threading.Event()

    def _spinner():
        idx = 1
        total_lines = len(block_lines) + footer_gap_lines + 1
        while not stop_event.is_set():
            try:
                sys.stdout.write(f"\x1b[{total_lines}A\r")
                frame_lines = assemble_frame(idx, colored=True)
                for line in frame_lines:
                    sys.stdout.write(pad + line + "\n")
                sys.stdout.write("\n" * footer_gap_lines)
                sys.stdout.write(footer_pad + footer + "\n")
                sys.stdout.flush()
            except Exception:
                break
            idx = (idx + 1) % WHEEL_FRAME_COUNT
            time.sleep(0.08)

    spinner_thread = threading.Thread(target=_spinner, daemon=True)
    spinner_thread.start()

    kr = KeyReader()
    try:
        with kr:
            while not stop_event.is_set():
                if kr.read_nonblocking(timeout=0.1) is not None:
                    break
    finally:
        stop_event.set()
        try:
            spinner_thread.join(timeout=0.5)
        except Exception:
            pass

    safe_clear()


def safe_clear() -> None:
    try:
        clear_screen()
    except Exception:
        pass


def init_color():
    try:
        from colorama import Fore, Style, init as colorama_init

        colorama_init()
        if os.environ.get("NO_COLOR"):
            return False, None, None
        return True, Fore, Style
    except Exception:
        return False, None, None


def supports_unicode_blocks() -> bool:
    try:
        enc = (sys.stdout.encoding or "").lower()
        if "utf" in enc:
            return True
        import locale as _locale

        return "utf" in (_locale.getpreferredencoding(False) or "").lower()
    except Exception:
        return False


def pick_block_chars() -> tuple[str, str]:
    use_blocks = supports_unicode_blocks() and not os.environ.get("MALCOLM_ASCII_ONLY")
    return ("█", "░") if use_blocks else ("#", "/")


def bake_glyphs(on_char: str, shadow_char: str) -> dict[str, list[str]]:
    def translate(raw_glyph: list[str]) -> list[str]:
        return [line.replace("█", on_char).replace("░", shadow_char) for line in raw_glyph]

    return {name: translate(lines) for name, lines in UNICODE_GLYPHS.items()}


def get_term_width() -> int:
    import shutil

    try:
        return shutil.get_terminal_size((80, 24)).columns
    except Exception:
        return 80


def build_wheel_frames(size: int, on_char: str) -> list[list[str]]:
    import math

    assert size % 2 == 1 and size >= 9
    r_outer = size // 2
    center = r_outer

    def blank_grid() -> list[list[str]]:
        return [[" "] * size for _ in range(size)]

    def draw_ring(grid: list[list[str]]) -> None:
        for y in range(size):
            for x in range(size):
                d = math.hypot(x - center, y - center)
                if r_outer - 0.5 <= d <= r_outer + 0.5:
                    grid[y][x] = on_char

    def draw_blades(grid: list[list[str]], theta: float) -> None:
        for arm in range(3):
            arm_angle = theta + (2.0 * math.pi * arm / 3.0)
            steps = int(r_outer * 5)
            for i in range(steps):
                t = i / float(steps)
                radius = (1.0 - t) * (r_outer - 1.2)
                angle = arm_angle - t * math.pi * 1.4
                fx = center + radius * math.cos(angle)
                fy = center + radius * math.sin(angle)
                brush_radius = (1.0 - t) * 1.1
                min_py = max(0, int(fy - brush_radius))
                max_py = min(size - 1, int(fy + brush_radius))
                min_px = max(0, int(fx - brush_radius))
                max_px = min(size - 1, int(fx + brush_radius))
                for py in range(min_py, max_py + 1):
                    for px in range(min_px, max_px + 1):
                        if math.hypot(px - fx, py - fy) <= brush_radius and math.hypot(
                            px - center, py - center
                        ) < (r_outer - 0.7):
                            grid[py][px] = on_char

    frames: list[list[str]] = []
    for idx in range(WHEEL_FRAME_COUNT):
        theta = 2.0 * math.pi * (idx / WHEEL_FRAME_COUNT)
        grid = blank_grid()
        draw_ring(grid)
        draw_blades(grid, theta)
        frames.append(["".join(row) for row in grid])
    return frames


class KeyReader:
    """Cross-platform single-key reader with optional non-blocking mode."""

    def __init__(self) -> None:
        self._posix = os.name != "nt"
        self._fd = None
        self._old_settings = None

    def __enter__(self):
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            return self
        if self._posix:
            try:
                import termios  # type: ignore
                import tty  # type: ignore

                self._fd = sys.stdin.fileno()
                self._old_settings = termios.tcgetattr(self._fd)
                tty.setcbreak(self._fd)
            except Exception:
                self._fd = None
                self._old_settings = None
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._posix and self._fd is not None and self._old_settings is not None:
            try:
                import termios  # type: ignore

                termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old_settings)
            except Exception:
                pass

    def read_nonblocking(self, timeout: float = 0.1):
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            return None

        if self._posix:
            try:
                import select  # type: ignore

                readable, _, _ = select.select([sys.stdin], [], [], timeout)
                if readable:
                    try:
                        return sys.stdin.read(1)
                    except Exception:
                        return ""
            except Exception:
                return None
            return None
        else:
            try:
                import msvcrt  # type: ignore
                import time as _t

                end = _t.time() + timeout
                while _t.time() < end:
                    if msvcrt.kbhit():
                        try:
                            ch = msvcrt.getwch()
                        except Exception:
                            ch = ""
                        return ch
                    _t.sleep(0.02)
            except Exception:
                return None
            return None

    def wait_for_key(self, prompt: str | None = None) -> None:
        if prompt:
            sys.stdout.write(prompt)
            sys.stdout.flush()

        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            try:
                input("")
            except Exception:
                pass
            finally:
                sys.stdout.write("\n")
                sys.stdout.flush()
            return

        try:
            with self:
                while True:
                    if self.read_nonblocking(timeout=0.1) is not None:
                        break
        except KeyboardInterrupt:
            pass
        finally:
            sys.stdout.write("\n")
            sys.stdout.flush()
