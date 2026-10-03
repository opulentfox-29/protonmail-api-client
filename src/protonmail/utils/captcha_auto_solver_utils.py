"""
Utils for auto solve CAPTCHA downloaded from the other repository:

https://github.com/gravilk/protonmail-documented/
"""

import hashlib
import time
from typing import Optional

import cv2
import numpy as np

X_OFFSET = -27  # Puzzle offsets are static. It was found by trial and error
Y_OFFSET = -34


def solve_challenge(challenge: str, n_zeros: int) -> int:
    """ Solve CAPTCHA challenge. """
    curr = 0
    while True:
        input_str = f'{curr}{challenge}'
        result = hashlib.sha256(input_str.encode()).hexdigest()

        j = (n_zeros + 3) // 4
        k = result[:j]
        l = int(k, 16)

        if l < 2 ** (4 * j - n_zeros):
            return curr
        else:
            curr += 1


def solve_challenges(challenges: list[str], n_zeros: int) -> tuple[list[int], float]:
    """Solve CAPTCHA proof-of-work challenges and return elapsed milliseconds."""
    start = time.perf_counter()
    answers = [solve_challenge(challenge, n_zeros) for challenge in challenges]
    elapsed = (time.perf_counter() - start) * 1000
    return answers, elapsed


def get_captcha_puzzle_coordinates(image_bytes: bytes, puzzle_image_bytes: Optional[bytes] = None) -> Optional[tuple[int, int]]:
    """Get CAPTCHA puzzle coordinates from the background image, or from both background and puzzle assets."""
    if puzzle_image_bytes is not None:
        try:
            background_np = np.frombuffer(image_bytes, np.uint8)
            background_img = cv2.imdecode(background_np, cv2.IMREAD_GRAYSCALE)
            puzzle_np = np.frombuffer(puzzle_image_bytes, np.uint8)
            puzzle_img = cv2.imdecode(puzzle_np, cv2.IMREAD_UNCHANGED)

            if background_img is None or puzzle_img is None:
                raise ValueError('Unable to decode CAPTCHA images')

            # PNG with alpha: the piece is opaque, its padding is transparent.
            # A grayscale decode would keep the padding's stored RGB and can swallow the piece silhouette.
            if puzzle_img.ndim == 3 and puzzle_img.shape[2] == 4:
                piece_visible = puzzle_img[:, :, 3] > 10
                puzzle_gray = cv2.cvtColor(puzzle_img[:, :, :3], cv2.COLOR_BGR2GRAY)
            else:
                puzzle_gray = puzzle_img if puzzle_img.ndim == 2 else cv2.cvtColor(puzzle_img, cv2.COLOR_BGR2GRAY)
                piece_visible = puzzle_gray > 30

            piece_mask = (piece_visible * 255).astype(np.uint8)
            piece_rows, piece_cols = np.nonzero(piece_mask)
            if piece_rows.size == 0:
                return None
            piece_y, piece_x = int(piece_rows.min()), int(piece_cols.min())
            piece_h = int(piece_rows.max() - piece_rows.min() + 1)
            piece_w = int(piece_cols.max() - piece_cols.min() + 1)

            # The piece is a crop of the background photo, so content matching is the strongest signal
            if piece_w >= 4 and piece_h >= 4:
                piece_crop = puzzle_gray[piece_y:piece_y + piece_h, piece_x:piece_x + piece_w]
                if piece_crop.std() >= 8:  # a flat-color piece carries no content signal
                    content_result = cv2.matchTemplate(background_img, piece_crop, cv2.TM_CCOEFF_NORMED)
                    _, content_max, _, content_loc = cv2.minMaxLoc(content_result)
                    if content_max >= 0.55:
                        return int(content_loc[0] - piece_x), int(content_loc[1] - piece_y)

            bright_slot = cv2.inRange(background_img, 180, 255)
            slot_contours, _ = cv2.findContours(bright_slot, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            slot_candidates = []
            for contour in slot_contours:
                x, y, w, h = cv2.boundingRect(contour)
                area = cv2.contourArea(contour)
                if (
                    abs(w - piece_w) <= 12
                    and abs(h - piece_h) <= 12
                    and area >= piece_w * piece_h * 0.25
                ):
                    slot_candidates.append((area, x, y))
            if slot_candidates:
                _, slot_x, slot_y = max(slot_candidates)
                return int(slot_x + 1), int(slot_y + 1)

            contours, _ = cv2.findContours(piece_mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            outline = np.zeros_like(piece_mask)
            cv2.drawContours(outline, contours, -1, color=255, thickness=1)
            if cv2.countNonZero(outline) > 0:
                blur_background = cv2.GaussianBlur(background_img, (3, 3), 0)
                edges_background = cv2.Canny(blur_background, 50, 150)

                result = cv2.matchTemplate(edges_background, outline, cv2.TM_CCOEFF_NORMED)
                _, max_val, _, max_loc = cv2.minMaxLoc(result)
                if max_val >= 0.1:
                    return int(max_loc[0]), int(max_loc[1])
        except Exception:
            pass

    np_array = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(np_array, cv2.IMREAD_COLOR)
    img_gray = cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)

    _, thresh = cv2.threshold(img_gray, 190, 255, cv2.THRESH_BINARY_INV)
    contours, hierarchy = cv2.findContours(thresh, cv2.RETR_CCOMP, cv2.CHAIN_APPROX_SIMPLE)
    hierarchy = hierarchy[0]

    for contour, sub_hierarchy in zip(contours, hierarchy):
        if sub_hierarchy[2] > 0 or sub_hierarchy[3] > 0:
            continue
        area = cv2.contourArea(contour)
        if 1700 < area < 1800:
            moments = cv2.moments(contour)
            coordinate_x = int(moments['m10'] / moments['m00']) + X_OFFSET
            coordinate_y = int(moments['m01'] / moments['m00']) + Y_OFFSET
            return coordinate_x, coordinate_y
    return None
