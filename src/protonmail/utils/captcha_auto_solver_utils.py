"""
Utils for auto solve CAPTCHA downloaded from the other repository:

https://github.com/gravilk/protonmail-documented/
"""

import hashlib
from typing import Optional

import cv2
import numpy as np

N_LEADING_ZEROS_REQUIRED = 13
X_OFFSET = -27  # Puzzle offsets are static. It was found by trial and error
Y_OFFSET = -34


def solve_challenge(challenge: str) -> int:
    """ Solve CAPTCHA challenge. """
    curr = 0
    while True:
        input_str = f'{curr}{challenge}'
        result = hashlib.sha256(input_str.encode()).hexdigest()

        j = (N_LEADING_ZEROS_REQUIRED + 3) // 4
        k = result[:j]
        l = int(k, 16)

        if l < 2 ** (4 * j - N_LEADING_ZEROS_REQUIRED):
            return curr
        else:
            curr += 1


def get_captcha_puzzle_coordinates(image_bytes: bytes) -> Optional[tuple[int, int]]:
    """ Get CAPTCHA puzzle coordinates. """
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
