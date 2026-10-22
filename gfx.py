"""
gfx.py - high quality artwork for CyberShield AI.

Everything is drawn with Pillow at the *real* pixel size of the widget
(with super-sampling + glow), so nothing is up-scaled and nothing is blurry
or pixelated, whatever the screen DPI is.
"""

import math
import random

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

SS = 3  # super-sampling factor for crisp edges


# ------------------------------------------------------------------
# small helpers
# ------------------------------------------------------------------

def hex_rgb(c):
    c = c.lstrip("#")
    return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))


def lerp(a, b, t):
    return a + (b - a) * t


def mix(c1, c2, t):
    a, b = hex_rgb(c1), hex_rgb(c2)
    return tuple(int(lerp(a[i], b[i], t)) for i in range(3))


def _font(size, bold=True):
    names = (
        ["segoeuib.ttf", "arialbd.ttf", "DejaVuSans-Bold.ttf", "Arial Bold.ttf"]
        if bold else
        ["segoeui.ttf", "arial.ttf", "DejaVuSans.ttf", "Arial.ttf"]
    )
    for name in names:
        try:
            return ImageFont.truetype(name, int(size))
        except Exception:
            continue
    try:
        return ImageFont.load_default(size=int(size))
    except Exception:
        return ImageFont.load_default()


class Canvas:
    """Float RGB accumulator with additive glow layers."""

    def __init__(self, w, h, base=(2, 8, 20)):
        self.w, self.h = w, h
        self.acc = np.zeros((h, w, 3), np.float32)
        self.acc[:] = np.array(base, np.float32) / 255.0

    @staticmethod
    def new_layer(w, h, ss=SS):
        return Image.new("RGBA", (w * ss, h * ss), (0, 0, 0, 0))

    def _premult(self, layer):
        if layer.size != (self.w, self.h):
            layer = layer.resize((self.w, self.h), Image.LANCZOS)
        a = np.asarray(layer, np.float32) / 255.0
        return a[..., :3] * a[..., 3:4]

    def add(self, layer, gain=1.0, glow=(), over=False):
        """layer: RGBA image. glow: iterable of (radius, gain)."""
        pm = self._premult(layer)
        if over:
            alpha = np.asarray(
                layer.resize((self.w, self.h), Image.LANCZOS) if layer.size != (self.w, self.h) else layer,
                np.float32)[..., 3:4] / 255.0
            self.acc = self.acc * (1 - alpha) + pm
        else:
            self.acc += pm * gain
        for radius, g in glow:
            im = Image.fromarray(np.clip(pm * 255, 0, 255).astype(np.uint8), "RGB")
            blur = np.asarray(im.filter(ImageFilter.GaussianBlur(radius)), np.float32) / 255.0
            self.acc += blur * g

    def add_array(self, arr, gain=1.0):
        self.acc += arr * gain

    def image(self):
        out = 1.0 - np.exp(-np.clip(self.acc, 0, None) * 1.35)   # soft tone-map
        out = np.clip(out * 1.0, 0, 1)
        return Image.fromarray((out * 255).astype(np.uint8), "RGB")

    def raw_image(self):
        return Image.fromarray((np.clip(self.acc, 0, 1) * 255).astype(np.uint8), "RGB")


def radial_gradient(w, h, cx, cy, radius, inner, outer, power=1.6):
    yy, xx = np.mgrid[0:h, 0:w].astype(np.float32)
    d = np.sqrt((xx - cx) ** 2 + (yy - cy) ** 2) / radius
    t = np.clip(1 - d, 0, 1) ** power
    inner = np.array(inner, np.float32) / 255.0
    outer = np.array(outer, np.float32) / 255.0
    return outer[None, None, :] + (inner - outer)[None, None, :] * t[..., None]


# ------------------------------------------------------------------
# WORLD GEOGRAPHY (lon, lat) - hand built coastlines for the dot-matrix map
# ------------------------------------------------------------------

LAND = {
    "north_america": [
        (-166, 68), (-156, 71.3), (-141, 69.6), (-128, 70.2), (-115, 68.7), (-100, 68), (-95, 71),
        (-85, 69.5), (-82, 67), (-90, 64), (-94, 60), (-92, 57), (-85, 55), (-82, 52.5), (-79, 51.5),
        (-78, 55), (-77, 58), (-78, 62), (-72, 62.5), (-65, 60.5), (-61, 56), (-57, 53), (-55.5, 52),
        (-60, 50), (-66, 50), (-71, 47), (-65, 48.5), (-64, 46), (-61, 45.5), (-66, 44), (-70, 43.5),
        (-70.5, 41.8), (-74, 40.5), (-75.5, 38), (-76, 35), (-78, 33.8), (-81, 31.5), (-81, 29.5),
        (-80, 26.5), (-80.5, 25.2), (-82, 26.5), (-82.7, 28), (-84, 30), (-86, 30.3), (-89, 30.2),
        (-90, 29), (-93, 29.7), (-97, 27.8), (-97.5, 25), (-97.8, 22), (-96, 19), (-94.5, 18.2),
        (-91, 19), (-90.5, 21), (-87, 21.5), (-88, 18), (-88.5, 15.8), (-85, 15.8), (-83.3, 15),
        (-83.5, 11), (-81.5, 9), (-79, 9.5), (-77.5, 8.5), (-78.5, 7.5), (-80, 7.3), (-82, 8),
        (-84, 9.8), (-86, 11), (-87.5, 13), (-91, 14), (-94, 16), (-97, 16), (-101, 17.6),
        (-105.5, 20), (-105.7, 22), (-108, 25.5), (-110.5, 28.5), (-112.5, 31), (-114.7, 31.7),
        (-114.8, 32.7), (-117, 32.5), (-118.5, 34), (-121, 35), (-122.5, 37.7), (-124, 40.3),
        (-124.3, 43), (-124, 46.2), (-124.7, 48.3), (-122.5, 48), (-123, 49.5), (-127, 50.5),
        (-130, 54), (-132, 56), (-135, 58.5), (-140, 59.8), (-146, 60.5), (-150, 59.5),
        (-152, 58), (-158, 56.5), (-163, 55), (-158, 58.5), (-162, 59.5), (-165, 61), (-166, 64),
        (-168, 65.5),
    ],
    "baja": [(-117, 32.5), (-114.7, 31.7), (-112.8, 28.5), (-110, 24.5), (-109.5, 23), (-112, 24.8),
             (-114.5, 28), (-116, 30.5)],
    "chukotka": [(-180, 69), (-175, 67.5), (-170, 66), (-172, 64.5), (-180, 65)],
    "greenland": [(-73, 78.5), (-68, 76), (-60, 75.8), (-56, 73), (-55, 70), (-53, 67.5), (-51, 64),
                  (-48, 61), (-43.5, 60), (-41, 62.5), (-38, 65.5), (-30, 68), (-22, 70.5),
                  (-22, 73), (-19, 76), (-18, 80), (-30, 83.4), (-45, 82.7), (-60, 82), (-70, 80.5)],
    "baffin": [(-90, 73.5), (-80, 73.8), (-72, 71.5), (-66, 69), (-62, 66.5), (-65.5, 63),
               (-72, 63.5), (-77, 65), (-72, 68), (-81, 69), (-89, 70)],
    "ellesmere": [(-90, 77), (-80, 76), (-70, 78.5), (-62, 82), (-80, 83), (-92, 81)],
    "victoria": [(-118, 70), (-110, 73), (-102, 73), (-100, 70), (-106, 68.8), (-114, 69)],
    "newfoundland": [(-59, 47.6), (-53, 46.7), (-52.7, 47.7), (-55.5, 51.5), (-57.5, 50.5)],
    "cuba": [(-85, 21.9), (-82, 23.2), (-77, 21.8), (-74.2, 20.2), (-77.5, 19.9), (-80, 21.5)],
    "hispaniola": [(-74.4, 18.5), (-72.5, 19.9), (-69, 19.3), (-68.4, 18.6), (-71, 17.9), (-73.8, 18)],
    "south_america": [
        (-77, 8.5), (-75.5, 10.8), (-72, 12.2), (-71, 11), (-68, 10.5), (-64, 10.5), (-61.5, 10.7),
        (-60, 8.5), (-57, 6), (-52, 5), (-50, 1.5), (-50, -0.5), (-48, -1), (-44.5, -2.5),
        (-40, -2.8), (-35.2, -5.5), (-34.8, -8), (-37, -11.5), (-39, -14), (-39.2, -17.8),
        (-41, -22), (-44, -23), (-48, -26), (-48.8, -28.5), (-52, -32), (-54, -34.6), (-58, -34.5),
        (-57.5, -36.5), (-57, -38), (-62, -39), (-65, -41), (-63.5, -42.5), (-65.5, -45),
        (-67.5, -46.5), (-66, -48), (-68.5, -50.5), (-69, -52.5), (-68.5, -54), (-65, -55),
        (-70, -55.3), (-74, -52), (-75, -48), (-74, -43), (-73.5, -38), (-71.5, -32), (-71.5, -28),
        (-70.3, -18.5), (-75, -15), (-78, -11), (-81, -6), (-81, -4), (-79.8, -2), (-80.5, -1),
        (-80, 1), (-78.8, 1.5), (-77.5, 4), (-77.3, 7),
    ],
    "eurasia": [
        (-9, 37), (-9.5, 39), (-8.8, 42), (-9.3, 43.2), (-8, 43.7), (-1.8, 43.4), (-1.2, 46),
        (-2.5, 47.3), (-4.5, 48.2), (-1.5, 48.7), (-1.5, 49.7), (1.5, 50.1), (3, 51.2),
        (4.5, 52.5), (7, 53.5), (8.5, 54), (8.3, 55.5), (8.2, 57.2), (10.5, 57.7), (10.5, 56),
        (9.7, 55), (11, 54), (14, 54), (18, 54.7), (21, 55), (21, 57), (24, 57.3), (24, 59.4),
        (28, 59.5), (30, 60), (26, 60.4), (22.5, 60), (21.5, 61.2), (21.3, 63), (24, 64.8),
        (25.5, 65.3), (22, 65.7), (21, 64), (18.5, 62.5), (17.2, 61), (17.5, 60), (18.8, 59.4),
        (16.5, 58.5), (16.5, 57), (15, 56), (13, 55.5), (12.5, 56.5), (11.7, 58), (10.5, 59),
        (8, 58), (6, 58.5), (5, 60), (5, 62), (8, 63.5), (12, 66), (14, 68), (17, 69.5), (21, 70),
        (25, 71), (30, 70), (33, 69.8), (41, 67.5), (40, 66), (36, 66), (34, 64.5), (38, 64.5),
        (41, 66), (44, 66.5), (44, 68), (53, 68.5), (60, 69), (68, 69), (70, 73), (80, 73.5),
        (87, 75), (100, 77.5), (105, 77), (113, 74), (125, 73.5), (140, 72.5), (150, 71.5),
        (160, 69.7), (170, 70), (180, 68.9), (180, 65), (177, 62.5), (170, 60), (163, 59.5),
        (162, 58), (163, 57), (162, 55), (160, 53), (156.5, 51), (156, 53), (158, 56),
        (155.5, 57.5), (152, 59), (143, 59.2), (137, 54), (141, 52.5), (140.5, 50), (140, 48),
        (135.5, 43.5), (131, 42.5), (129.5, 41), (128, 38.5), (129.5, 36), (129, 35), (126.5, 34.5),
        (126.5, 37), (125, 39.5), (121.5, 39), (121, 40.5), (118, 39), (119, 37), (122.5, 37),
        (120, 36), (121, 34), (121.5, 31.5), (122, 30), (121, 28), (119.5, 25.5), (116.5, 23),
        (113.5, 22.2), (110.5, 21), (109.5, 19.5), (108, 21.5), (106.5, 20), (105.7, 18.5),
        (108.8, 15), (109.2, 12), (107, 10.5), (105, 8.6), (104.8, 10.5), (103, 10.8), (100.5, 13.3),
        (99.5, 10.5), (100.3, 7), (102, 6), (103.5, 4.5), (103.5, 1.5), (101.5, 2.5), (100.5, 5.5),
        (99.5, 8), (98.5, 10), (98.5, 13.5), (97.5, 16.5), (94.5, 16), (94, 19), (92, 21),
        (91.5, 22.5), (89, 22), (87, 21.4), (86.5, 20), (84.5, 18.5), (82, 16.5), (80.2, 15.5),
        (80, 13), (79.8, 10.3), (78, 8.3), (77, 8.1), (76.2, 10), (75, 12.5), (73.8, 15.5),
        (72.8, 19), (72.8, 21.2), (70, 20.8), (68.7, 23), (67, 24.7), (66, 25.4), (61.5, 25.1),
        (57, 25.7), (56.4, 27), (54, 26.7), (51.5, 27.8), (50, 30), (48.8, 30), (50.5, 26),
        (51.5, 24.5), (54, 24.2), (56, 26), (56.5, 24.5), (58.5, 23.5), (59.8, 22.5), (58, 20.5),
        (55, 17.2), (52, 16), (49, 14.2), (45, 12.8), (43.3, 12.7), (42.8, 15), (42.5, 17),
        (40.5, 20.5), (39, 22), (37, 25), (35, 28.2), (34.8, 29.5), (34.9, 31), (35.2, 33),
        (35.8, 34.6), (36, 36.5), (34.5, 36.8), (32.5, 36.1), (30.5, 36.5), (29, 36.7), (27.4, 37),
        (26.3, 38.2), (26.8, 39.5), (26.2, 40.1), (26, 40.8), (24, 40.7), (22.5, 40), (24, 38),
        (23.8, 38), (22.8, 36.5), (21.5, 37.2), (21, 39), (19.5, 40.5), (19, 42), (16, 43.5),
        (13.7, 45.6), (12.4, 44.5), (13.6, 43.6), (14.2, 42.2), (16, 41.9), (18.5, 40.2),
        (17, 39.8), (16.5, 38.9), (16, 38), (15.7, 40), (14, 40.8), (12.5, 41.5), (10.5, 43),
        (8.8, 44.3), (7.5, 43.8), (4.5, 43.4), (3.2, 42.4), (3.2, 41.7), (0.8, 41), (-0.3, 39.5),
        (-0.2, 38.5), (-1, 37.5), (-2.2, 36.7), (-4.5, 36.7), (-5.5, 36), (-6.3, 36.7),
    ],
    "africa": [
        (32.3, 31.3), (29, 30.9), (25, 31.6), (23, 32.6), (20, 32.1), (19.7, 30.5), (17, 31.2),
        (15.2, 32.3), (11.5, 33), (10.2, 33.6), (11, 35.2), (10, 37.2), (8, 36.9), (5, 36.8),
        (2, 36.6), (-1, 35.5), (-2.5, 35.2), (-5.5, 35.8), (-6.8, 34), (-9.5, 31), (-10, 29),
        (-13, 27.7), (-15, 24.5), (-17, 21), (-16.5, 19), (-16.2, 16), (-17.2, 14.7),
        (-16.7, 13), (-15, 11), (-13.5, 9.5), (-11.5, 7.5), (-8.5, 4.4), (-4, 5.2), (-1, 4.7),
        (1.5, 6), (4.5, 6.2), (6.2, 4.3), (8.5, 4.5), (9.5, 3.5), (9.5, 2), (9.5, -1),
        (11.5, -3.5), (12.3, -6), (13.5, -9), (13.5, -12), (12, -17), (12.5, -18), (14.5, -22.5),
        (15.2, -27), (17, -29), (18, -32), (18.5, -34.2), (20, -34.8), (22, -34), (25.5, -34),
        (27.5, -33.2), (30, -31), (32.5, -28.5), (32.8, -26), (34.7, -24), (35.5, -22),
        (35, -19.8), (36.8, -18), (40.5, -15), (40.5, -11), (39.2, -7), (38.8, -6), (39.7, -4.5),
        (40.9, -2.5), (42, -0.5), (44, 1.8), (46, 2.5), (48, 5), (51, 10.5), (51.2, 11.8),
        (48, 11.2), (44, 10.5), (43.2, 11.8), (41.5, 14.5), (39.5, 16), (38.5, 18), (37, 21),
        (35.5, 24), (34, 27), (33, 28.5), (32.8, 29.8),
    ],
    "madagascar": [(49.5, -12), (50.5, -15), (49.8, -17.5), (47.5, -24.5), (45, -25.5),
                   (43.5, -23), (44.5, -19), (44.2, -16.5), (46.5, -15.5)],
    "uk": [(-5.7, 50), (-3, 50.6), (1.4, 51.2), (1.7, 52.7), (0.2, 53.4), (-0.2, 54.5), (-1.6, 55.6),
           (-2.5, 56.2), (-1.8, 57.5), (-4, 57.7), (-3.2, 58.6), (-5, 58.6), (-6.2, 56.8),
           (-5.2, 55.3), (-4.8, 54.8), (-3.2, 54.8), (-3, 53.4), (-4.5, 53.2), (-4.2, 52.2),
           (-5.2, 51.7), (-3.3, 51.4), (-4.5, 51)],
    "ireland": [(-10, 51.7), (-6, 52.2), (-6, 54.2), (-5.5, 55.2), (-7.5, 55.2), (-8.8, 54.2),
                (-10, 53.8)],
    "iceland": [(-24, 65.5), (-22, 66.4), (-16, 66.4), (-13.5, 65), (-15, 64), (-19, 63.4),
                (-22.5, 63.8)],
    "honshu": [(130.9, 33.9), (132.5, 35.4), (135.5, 35.6), (136.8, 37.3), (139.3, 38.2), (140, 40.5),
               (141.5, 41), (141.9, 39), (140.9, 37), (140.8, 35.7), (139.8, 35), (138, 34.6),
               (136.8, 34.3), (135.2, 33.5), (134.5, 34.4), (132.5, 34.2)],
    "hokkaido": [(140, 42), (141.5, 43.3), (145.5, 43.3), (143.2, 42), (141.5, 42.5)],
    "kyushu": [(129.8, 33), (131.8, 33.3), (131.5, 31), (130.3, 31.3)],
    "sakhalin": [(142, 46), (143, 49), (144.5, 49.5), (143, 53), (142.5, 54), (142, 51)],
    "sri_lanka": [(79.8, 9.5), (81.8, 7.5), (81, 6), (80, 6.5)],
    "taiwan": [(120.2, 23), (121.5, 25.2), (121.8, 24.5), (120.8, 22)],
    "luzon": [(120.5, 18.5), (122.2, 18.4), (122, 16), (124, 13.8), (123, 13.2), (121, 13.8), (120.5, 16)],
    "mindanao": [(122, 8), (126.5, 9.5), (126, 6.5), (124, 6.3), (122.5, 7)],
    "borneo": [(109, 1.5), (111, 2.5), (113, 3.2), (115.5, 5.2), (117.5, 7), (119, 5.2), (117.5, 4),
               (118.5, 1), (117, -1), (116.5, -3.8), (114.5, -4), (111.7, -3), (110, -2.8),
               (109, -1), (109.2, 0.5)],
    "sumatra": [(95.3, 5.5), (97.5, 5.2), (100, 2), (103.5, -1), (106, -3), (105.8, -5.8),
                (104, -5.8), (101, -3), (98.5, 0.5), (96, 3)],
    "java": [(105.5, -6.7), (108, -6.3), (111, -6.5), (114.5, -7.8), (114.5, -8.7), (111, -8.3),
             (108, -7.8), (106, -7.3)],
    "sulawesi": [(119.5, -5.5), (120.5, -3), (119, -0.5), (120, 1), (123.5, 1.2), (125, 1.5),
                 (122, -1), (123, -4), (121.5, -4.8), (120.5, -5.5)],
    "new_guinea": [(131, -0.8), (134, -1), (138, -1.7), (141, -2.7), (145, -4.5), (147.5, -6),
                   (147.8, -8), (150.5, -10.5), (147, -10), (143.5, -8.5), (141, -9.2),
                   (138.5, -8.2), (137.5, -5.5), (135, -4.2), (132.5, -3.5)],
    "australia": [(113.5, -22), (114, -26), (115, -30), (115, -34.2), (118, -35), (122, -34),
                  (124, -33), (129, -31.6), (131, -31.5), (134, -32.5), (137, -34), (138, -35.2),
                  (140, -37.8), (144, -38.5), (147, -39), (150, -37.3), (151.5, -33), (153.2, -28),
                  (153, -25), (150.5, -22.5), (148.5, -20), (146, -18.5), (145.5, -15), (143.5, -14),
                  (142.5, -10.8), (141.5, -13), (141.5, -17.5), (139, -17.2), (137, -15.5),
                  (135.5, -15), (136.8, -12.2), (132.5, -11.5), (130.5, -12.3), (129.5, -15),
                  (127.5, -14), (125.5, -15), (123.5, -17), (122, -18), (120, -20), (116.5, -20.7),
                  (114.5, -22)],
    "tasmania": [(144.7, -40.7), (148.3, -40.9), (148, -43.2), (146, -43.6)],
    "nz_north": [(172.8, -34.5), (174.5, -36.5), (176, -37.5), (178.5, -37.7), (177, -39.5),
                 (175, -41.5), (174.5, -39.5), (173.7, -39.2), (174.8, -37.5)],
    "nz_south": [(172.7, -40.5), (174, -41.5), (173, -43.5), (171, -44.5), (170, -46.5),
                 (166.5, -46), (168, -44), (171, -42)],
}

WATER = {
    "black_sea": [(28, 42), (28, 44.3), (30, 45.5), (33, 46.2), (35, 45.2), (36.8, 45.2), (38, 47),
                  (39.5, 46.8), (38, 45), (40, 43.5), (41.5, 41.5), (37, 41), (35, 42), (32, 41.8),
                  (29, 41.2)],
    "caspian": [(47, 45), (49, 46.5), (53, 46.8), (53.5, 45), (51.5, 44.5), (51, 42.5), (52.8, 41.3),
                (53, 39), (53.8, 37.5), (51, 36.8), (49, 37.5), (49.5, 40), (48, 42), (47.5, 43.5)],
}

LON0, LON1 = -180.0, 180.0
LAT0, LAT1 = 84.0, -58.0      # top / bottom latitude of the map band
MASK_RES = 4                   # mask pixels per degree

_mask_cache = {}


def land_mask():
    if "m" in _mask_cache:
        return _mask_cache["m"]
    w = int((LON1 - LON0) * MASK_RES)
    h = int((LAT0 - LAT1) * MASK_RES)
    img = Image.new("L", (w, h), 0)
    d = ImageDraw.Draw(img)

    def px(poly):
        return [((lon - LON0) * MASK_RES, (LAT0 - lat) * MASK_RES) for lon, lat in poly]

    for poly in LAND.values():
        d.polygon(px(poly), fill=255)
    for poly in WATER.values():
        d.polygon(px(poly), fill=0)
    m = np.asarray(img, np.float32) / 255.0
    _mask_cache["m"] = m
    return m


# ------------------------------------------------------------------
# MAP + SHIELD
# ------------------------------------------------------------------

# real geographic hot-spots (lon, lat, size, kind)
HOTSPOTS = [
    (-74.0, 40.7, 1.0, "Malware"),      # New York
    (-87.6, 41.9, 0.5, "Phishing"),     # Chicago
    (-118.2, 34.0, 0.6, "Ransomware"),  # Los Angeles
    (-99.1, 19.4, 0.45, "Phishing"),    # Mexico City
    (-46.6, -23.5, 0.6, "Malware"),     # Sao Paulo
    (-74.1, 4.7, 0.4, "Phishing"),      # Bogota
    (-0.1, 51.5, 0.7, "Ransomware"),    # London
    (13.4, 52.5, 1.0, "Malware"),       # Berlin
    (37.6, 55.8, 0.7, "Phishing"),      # Moscow
    (31.2, 30.0, 0.45, "Malware"),      # Cairo
    (3.4, 6.5, 0.4, "Phishing"),        # Lagos
    (28.0, -26.2, 0.5, "Ransomware"),   # Johannesburg
    (72.9, 19.0, 0.6, "Malware"),       # Mumbai
    (116.4, 39.9, 0.7, "Phishing"),     # Beijing
    (121.5, 31.2, 1.0, "Malware"),      # Shanghai
    (139.7, 35.7, 0.6, "Ransomware"),   # Tokyo
    (103.8, 1.35, 0.5, "Phishing"),     # Singapore
    (151.2, -33.9, 0.55, "Malware"),    # Sydney
]

TRIANGLES = [(0.027, 0.60), (0.134, 0.635), (0.087, 0.79), (0.965, 0.655), (0.902, 0.69),
             (0.837, 0.80), (0.16, 0.975), (0.867, 0.975), (0.23, 0.92)]


def map_geometry(w, h):
    """Pixel layout used by both the renderer and the app (for pulse sprites)."""
    mx0, mx1 = w * 0.012, w * 0.988
    my0, my1 = h * 0.015, h * 0.690
    cx, cy = w * 0.5, h * 0.655
    r = min(w * 0.155, h * 0.235)
    return {"mx0": mx0, "mx1": mx1, "my0": my0, "my1": my1, "cx": cx, "cy": cy, "r": r}


def project(lon, lat, w, h):
    g = map_geometry(w, h)
    x = g["mx0"] + (lon - LON0) / (LON1 - LON0) * (g["mx1"] - g["mx0"])
    y = g["my0"] + (LAT0 - lat) / (LAT0 - LAT1) * (g["my1"] - g["my0"])
    return x, y


def hotspot_pixels(w, h):
    return [(*project(lon, lat, w, h), size, kind) for lon, lat, size, kind in HOTSPOTS]


def _bezier(p0, p1, p2, n=40):
    pts = []
    for i in range(n + 1):
        t = i / n
        x = (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t ** 2 * p2[0]
        y = (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t ** 2 * p2[1]
        pts.append((x, y))
    return pts


def _circuit_paths(w, h, g, seed=5):
    """Neon circuit traces that run from the shield rings to the edges."""
    rnd = random.Random(seed)
    cx, cy, r = g["cx"], g["cy"], g["r"]
    paths = []
    for side in (-1, 1):
        # horizontal lanes
        lanes = [-0.55, -0.32, -0.12, 0.08, 0.28, 0.5, 0.7]
        for k, ly in enumerate(lanes):
            y = cy + ly * r
            x = cx + side * r * 1.02
            pts = [(x, y)]
            run = rnd.uniform(0.18, 0.42) * w
            x2 = x + side * run * 0.45
            pts.append((x2, y))
            bend = rnd.choice([-1, 1]) * rnd.uniform(0.04, 0.10) * h
            x3 = x2 + side * abs(bend)
            y3 = y + bend
            pts.append((x3, y3))
            x4 = cx + side * (w * rnd.uniform(0.40, 0.50))
            pts.append((x4, y3))
            if rnd.random() < 0.5:
                bend2 = rnd.choice([-1, 1]) * rnd.uniform(0.03, 0.08) * h
                pts.append((x4 + side * abs(bend2), y3 + bend2))
                pts.append((x4 + side * (abs(bend2) + w * 0.05), y3 + bend2))
            paths.append(pts)
        # lanes that leave from the lower half of the ring and fall downwards
        for k in range(4):
            ang = math.radians(rnd.uniform(35, 75))
            x = cx + side * r * math.cos(ang)
            y = cy + r * math.sin(ang)
            drop = rnd.uniform(0.06, 0.16) * h
            pts = [(x, y), (x + side * 0.03 * w, y + drop * 0.5),
                   (x + side * 0.03 * w, y + drop),
                   (x + side * rnd.uniform(0.08, 0.2) * w, y + drop + 0.04 * h)]
            paths.append(pts)
    return paths


def _triangle(draw, x, y, s, width, fill, outline):
    pts = [(x, y - s), (x - s * 0.95, y + s * 0.75), (x + s * 0.95, y + s * 0.75)]
    draw.polygon(pts, fill=fill, outline=outline)
    draw.line(pts + [pts[0]], fill=outline, width=width, joint="curve")
    bar = s * 0.5
    draw.line([(x, y - s * 0.35), (x, y + bar * 0.25)], fill=outline, width=max(1, int(width * 0.9)))
    d = max(1, int(width * 0.7))
    draw.ellipse([x - d, y + s * 0.42 - d, x + d, y + s * 0.42 + d], fill=outline)


_map_cache = {}


def render_map(w, h):
    """Return a crisp RGB PIL image (w x h) of the dot-matrix world map with the shield."""
    key = (w, h)
    if key in _map_cache:
        return _map_cache[key]

    g = map_geometry(w, h)
    cx, cy, r = g["cx"], g["cy"], g["r"]
    rnd = random.Random(3)
    cv = Canvas(w, h, base=(2, 7, 18))

    # --- atmosphere --------------------------------------------------
    cv.add_array(radial_gradient(w, h, cx, cy, max(w, h) * 0.75, (6, 38, 82), (0, 0, 0), 1.7), 1.0)
    cv.add_array(radial_gradient(w, h, w * 0.5, h * 0.18, w * 0.6, (4, 20, 44), (0, 0, 0), 1.4), 0.7)

    # --- lat / long graticule ---------------------------------------
    lay = cv.new_layer(w, h)
    d = ImageDraw.Draw(lay)
    for lon in range(-180, 181, 20):
        x, _ = project(lon, 0, w, h)
        d.line([(x * SS, g["my0"] * SS), (x * SS, g["my1"] * SS)], fill=(30, 96, 170, 34), width=1)
    for lat in range(-50, 81, 20):
        _, y = project(0, lat, w, h)
        d.line([(g["mx0"] * SS, y * SS), (g["mx1"] * SS, y * SS)], fill=(30, 96, 170, 34), width=1)
    cv.add(lay)

    # --- land: soft body + dot matrix ---------------------------------
    mask = land_mask()
    mh, mw = mask.shape
    pitch = max(4.6, w / 185.0)
    rowh = pitch * 0.866
    dots = Canvas.new_layer(w, h)
    dd = ImageDraw.Draw(dots)

    # soft land fill (blurred polygon mask projected to the canvas)
    mimg = Image.fromarray((mask * 255).astype(np.uint8), "L")
    land_box = (int(g["mx0"]), int(g["my0"]), int(g["mx1"]), int(g["my1"]))
    fill_img = mimg.resize((land_box[2] - land_box[0], land_box[3] - land_box[1]), Image.BILINEAR)
    fill = Image.new("L", (w, h), 0)
    fill.paste(fill_img, (land_box[0], land_box[1]))
    fill_np = np.asarray(fill.filter(ImageFilter.GaussianBlur(2.2)), np.float32) / 255.0
    land_col = np.array([8, 40, 82], np.float32) / 255.0
    cv.add_array(fill_np[..., None] * land_col[None, None, :], 0.55)

    hs = hotspot_pixels(w, h)
    y = g["my0"]
    row = 0
    while y < g["my1"]:
        x = g["mx0"] + (pitch / 2 if row % 2 else 0)
        while x < g["mx1"]:
            lon = LON0 + (x - g["mx0"]) / (g["mx1"] - g["mx0"]) * (LON1 - LON0)
            lat = LAT0 - (y - g["my0"]) / (g["my1"] - g["my0"]) * (LAT0 - LAT1)
            mx_ = int((lon - LON0) * MASK_RES)
            my_ = int((LAT0 - lat) * MASK_RES)
            if 0 <= mx_ < mw and 0 <= my_ < mh:
                # coverage over a small window -> clean coastlines
                x0_, x1_ = max(mx_ - 3, 0), min(mx_ + 4, mw)
                y0_, y1_ = max(my_ - 3, 0), min(my_ + 4, mh)
                cov = float(mask[y0_:y1_, x0_:x1_].mean())
                if cov > 0.5:
                    near = 0.0
                    for hx, hy, hsz, _k in hs:
                        dist = math.hypot(x - hx, y - hy)
                        near = max(near, hsz * max(0.0, 1 - dist / (w * 0.07)))
                    bright = 0.50 + 0.30 * rnd.random() + 0.35 * near
                    col = mix("#2F78C8", "#9EDBFF", min(1.0, bright))
                    rad = pitch * (0.20 + 0.06 * rnd.random() + 0.05 * near)
                    a = int(150 + 105 * min(1.0, bright))
                    dd.ellipse([(x - rad) * SS, (y - rad) * SS, (x + rad) * SS, (y + rad) * SS],
                               fill=(*col, a))
            x += pitch
        y += rowh
        row += 1
    cv.add(dots, 0.80, glow=[(1.4, 0.30), (5, 0.18)])

    # --- attack arcs --------------------------------------------------
    arcs = Canvas.new_layer(w, h)
    ad = ImageDraw.Draw(arcs)
    pairs = [(0, 7), (14, 0), (7, 14), (6, 0), (1, 6), (13, 8), (15, 0), (14, 17), (4, 6), (7, 11),
             (12, 7), (2, 14), (8, 0)]
    for i, j in pairs:
        p0, p2 = hs[i][:2], hs[j][:2]
        mid = ((p0[0] + p2[0]) / 2, (p0[1] + p2[1]) / 2 - abs(p0[0] - p2[0]) * 0.22 - 14)
        pts = [(x * SS, y * SS) for x, y in _bezier(p0, mid, p2)]
        ad.line(pts, fill=(255, 64, 90, 120), width=max(1, SS * 1))
    cv.add(arcs, 0.9, glow=[(2.5, 0.8)])

    # --- circuit traces ---------------------------------------------
    paths = _circuit_paths(w, h, g)
    tr = Canvas.new_layer(w, h)
    td = ImageDraw.Draw(tr)
    for pts in paths:
        sp = [(x * SS, y * SS) for x, y in pts]
        td.line(sp, fill=(40, 150, 255, 230), width=int(1.6 * SS), joint="curve")
        ex, ey = sp[-1]
        rr = 3.2 * SS
        td.ellipse([ex - rr, ey - rr, ex + rr, ey + rr], outline=(120, 210, 255, 255), width=int(1.2 * SS),
                   fill=(6, 30, 70, 255))
    cv.add(tr, 1.0, glow=[(2.2, 1.1), (7, 0.7)])

    # --- shield assembly ----------------------------------------------
    cv.add_array(radial_gradient(w, h, cx, cy, r * 1.9, (20, 110, 230), (0, 0, 0), 2.4), 0.42)

    disc = Canvas.new_layer(w, h)
    dd2 = ImageDraw.Draw(disc)
    C = (cx * SS, cy * SS)
    rr0 = r * 0.995 * SS
    dd2.ellipse([C[0] - rr0, C[1] - rr0, C[0] + rr0, C[1] + rr0], fill=(3, 15, 38, 245))
    cv.add(disc, over=True)

    sh = Canvas.new_layer(w, h)
    sd = ImageDraw.Draw(sh)

    def ring(rad, width, color):
        rr = rad * SS
        sd.ellipse([C[0] - rr, C[1] - rr, C[0] + rr, C[1] + rr], outline=color, width=int(width * SS))

    ring(r * 1.00, 2.6, (40, 150, 255, 255))
    ring(r * 0.93, 1.2, (110, 200, 255, 230))
    ring(r * 1.09, 1.0, (30, 110, 220, 150))
    ring(r * 1.20, 0.8, (30, 90, 190, 90))

    # tick marks between the two main rings
    for k in range(120):
        a = k / 120 * math.tau
        r0, r1 = r * 0.955, r * (0.985 if k % 5 else 0.99)
        sd.line([(C[0] + math.cos(a) * r0 * SS, C[1] + math.sin(a) * r0 * SS),
                 (C[0] + math.cos(a) * r1 * SS, C[1] + math.sin(a) * r1 * SS)],
                fill=(120, 200, 255, 200), width=max(1, SS // 2))

    # arcs of light on the outer ring
    for start, ext in ((200, 70), (330, 40), (95, 45)):
        rr = r * 1.09 * SS
        sd.arc([C[0] - rr, C[1] - rr, C[0] + rr, C[1] + rr], start, start + ext,
               fill=(150, 220, 255, 255), width=int(2.2 * SS))

    cv.add(sh, 1.0, glow=[(2, 0.8), (8, 0.7), (22, 0.4)])

    # shield body
    s = r * 0.50
    sx, sy = cx, cy - s * 0.02
    outline = [
        (sx, sy - s * 1.05), (sx + s * 0.72, sy - s * 0.78), (sx + s * 0.82, sy - s * 0.65),
        (sx + s * 0.82, sy + s * 0.05), (sx + s * 0.62, sy + s * 0.55), (sx + s * 0.30, sy + s * 0.88),
        (sx, sy + s * 1.05), (sx - s * 0.30, sy + s * 0.88), (sx - s * 0.62, sy + s * 0.55),
        (sx - s * 0.82, sy + s * 0.05), (sx - s * 0.82, sy - s * 0.65), (sx - s * 0.72, sy - s * 0.78),
    ]
    fill_l = Canvas.new_layer(w, h)
    ImageDraw.Draw(fill_l).polygon([(x * SS, y * SS) for x, y in outline], fill=(6, 40, 92, 230))
    cv.add(fill_l, over=True)

    body_l = Canvas.new_layer(w, h)
    bd = ImageDraw.Draw(body_l)
    sp = [(x * SS, y * SS) for x, y in outline]
    bd.line(sp + [sp[0]], fill=(110, 205, 255, 255), width=int(3.4 * SS), joint="curve")
    inner = [(sx + (x - sx) * 0.84, sy + (y - sy) * 0.84) for x, y in outline]
    isp = [(x * SS, y * SS) for x, y in inner]
    bd.line(isp + [isp[0]], fill=(40, 140, 255, 200), width=int(1.4 * SS), joint="curve")
    # lock
    lw, lh = s * 0.62, s * 0.50
    lx0, ly0 = sx - lw / 2, sy - s * 0.02
    sh_r = lw * 0.30
    bd.arc([(sx - sh_r) * SS, (ly0 - sh_r * 1.8) * SS, (sx + sh_r) * SS, (ly0 + sh_r * 0.4) * SS],
           180, 360, fill=(190, 235, 255, 255), width=int(s * 0.12 * SS))
    bd.line([((sx - sh_r) * SS, (ly0 - sh_r * 0.7) * SS), ((sx - sh_r) * SS, ly0 * SS)],
            fill=(190, 235, 255, 255), width=int(s * 0.12 * SS))
    bd.line([((sx + sh_r) * SS, (ly0 - sh_r * 0.7) * SS), ((sx + sh_r) * SS, ly0 * SS)],
            fill=(190, 235, 255, 255), width=int(s * 0.12 * SS))
    bd.rounded_rectangle([lx0 * SS, ly0 * SS, (lx0 + lw) * SS, (ly0 + lh) * SS],
                         radius=int(s * 0.09 * SS), fill=(170, 225, 255, 255))
    kx, ky = sx, ly0 + lh * 0.42
    bd.ellipse([(kx - s * 0.06) * SS, (ky - s * 0.06) * SS, (kx + s * 0.06) * SS, (ky + s * 0.06) * SS],
               fill=(8, 50, 110, 255))
    bd.rectangle([(kx - s * 0.022) * SS, ky * SS, (kx + s * 0.022) * SS, (ky + s * 0.17) * SS],
                 fill=(8, 50, 110, 255))
    cv.add(body_l, 1.0, glow=[(2, 0.7), (7, 0.6), (18, 0.35)])

    # --- hot-spots (static glow, animated rings are drawn by the app) -----
    hot = Canvas.new_layer(w, h)
    hd = ImageDraw.Draw(hot)
    for x, y, size, _kind in hs:
        rr = (2.4 + 2.6 * size) * SS
        hd.ellipse([x * SS - rr, y * SS - rr, x * SS + rr, y * SS + rr], fill=(255, 70, 90, 255))
        r2 = rr * 0.45
        hd.ellipse([x * SS - r2, y * SS - r2, x * SS + r2, y * SS + r2], fill=(255, 220, 220, 255))
    cv.add(hot, 1.0, glow=[(3, 1.4), (9, 1.2), (20, 0.8)])

    # --- warning triangles ----------------------------------------------
    tri = Canvas.new_layer(w, h)
    tdr = ImageDraw.Draw(tri)
    sz = max(9, w * 0.016)
    for fx, fy in TRIANGLES:
        _triangle(tdr, fx * w * SS, fy * h * SS, sz * SS, int(1.8 * SS), (45, 6, 16, 235), (255, 70, 95, 255))
    cv.add(tri, 1.0, glow=[(2.5, 1.0), (8, 0.9)])

    # --- film grain / scanlines (texture) ------------------------------
    grain = np.random.default_rng(7).normal(0, 0.012, (h, w, 1)).astype(np.float32)
    cv.add_array(np.repeat(grain, 3, axis=2), 1.0)
    scan = np.ones((h, w, 1), np.float32)
    scan[::3] = 0.965
    cv.acc *= scan

    # vignette
    yy, xx = np.mgrid[0:h, 0:w].astype(np.float32)
    v = 1 - 0.55 * (((xx - w / 2) / (w * 0.62)) ** 2 + ((yy - h * 0.5) / (h * 0.72)) ** 2)
    cv.acc *= np.clip(v, 0.35, 1.0)[..., None]

    img = cv.image()
    if len(_map_cache) > 6:
        _map_cache.clear()
    _map_cache[key] = img
    return img


def pulse_frames(size, n=16, color=(255, 64, 90)):
    """RGBA sprites of an expanding, fading ring (used for animated hot-spots)."""
    frames = []
    for i in range(n):
        t = i / n
        big = Image.new("RGBA", (size * SS, size * SS), (0, 0, 0, 0))
        d = ImageDraw.Draw(big)
        c = size * SS / 2
        rad = (0.10 + 0.40 * t) * size * SS
        alpha = int(235 * (1 - t) ** 1.6)
        d.ellipse([c - rad, c - rad, c + rad, c + rad], outline=(*color, alpha), width=int(1.6 * SS))
        glow = big.filter(ImageFilter.GaussianBlur(2.2 * SS))
        out = Image.alpha_composite(glow, big)
        frames.append(out.resize((size, size), Image.LANCZOS))
    return frames


# ------------------------------------------------------------------
# CHARTS
# ------------------------------------------------------------------

def render_area(w, h, values, line="#E0303F", top="#7A1420", bottom="#030C18", bg="#030C18", glow_gain=0.7):
    """Smooth gradient area / sparkline chart."""
    w, h = max(int(w), 8), max(int(h), 8)
    cv = Canvas(w, h, base=hex_rgb(bg))
    lo, hi = min(values), max(values)
    span = (hi - lo) or 1
    pad = 4
    pts = []
    for i, v in enumerate(values):
        x = i * (w - 1) / (len(values) - 1)
        y = pad + (1 - (v - lo) / span) * (h - pad * 2 - 2)
        pts.append((x, y))

    # gradient fill under the line
    mask = Image.new("L", (w * SS, h * SS), 0)
    md = ImageDraw.Draw(mask)
    md.polygon([(0, h * SS)] + [(x * SS, y * SS) for x, y in pts] + [(w * SS, h * SS)], fill=255)
    mask = mask.resize((w, h), Image.LANCZOS)
    m = np.asarray(mask, np.float32)[..., None] / 255.0
    xs = np.array([p[0] for p in pts], np.float32)
    ys = np.array([p[1] for p in pts], np.float32)
    line_y = np.interp(np.arange(w, dtype=np.float32), xs, ys)[None, :]
    yy = np.arange(h, dtype=np.float32)[:, None]
    t = np.clip((yy - line_y) / (h * 0.85), 0, 1)[..., None]
    ct, cb = np.array(hex_rgb(top), np.float32) / 255, np.array(hex_rgb(bottom), np.float32) / 255
    grad = ct[None, None, :] * (1 - t) + cb[None, None, :] * t
    cv.acc = cv.acc * (1 - m) + grad * m

    ln = Canvas.new_layer(w, h)
    d = ImageDraw.Draw(ln)
    sp = [(x * SS, y * SS) for x, y in pts]
    d.line(sp, fill=(*hex_rgb(line), 255), width=int(1.8 * SS), joint="curve")
    cv.add(ln, 1.0, glow=[(2.2, glow_gain)])
    return cv.raw_image()


def _clockwise_donut(size, weights, colors, bg, thickness, gap_deg, start_deg):
    """start_deg: angle in PIL convention (0 = 3 o'clock, clockwise)."""
    cv = Canvas(size, size, base=hex_rgb(bg))
    ly = Canvas.new_layer(size, size)
    d = ImageDraw.Draw(ly)
    c = size * SS / 2
    R = size * SS * (0.5 - 0.07)
    wdt = int(size * SS * thickness)
    total = float(sum(weights))
    ang = start_deg
    for wt, col in zip(weights, colors):
        ext = 360.0 * wt / total
        d.arc([c - R, c - R, c + R, c + R], ang + gap_deg / 2, ang + ext - gap_deg / 2,
              fill=(*hex_rgb(col), 255), width=wdt)
        ang += ext
    cv.add(ly, 1.0, glow=[(size * 0.02, 0.45)])
    return cv.raw_image()


def render_donut2(size, weights, colors, bg="#030C18", thickness=0.13, gap_deg=3.0, start_deg=-95):
    return _clockwise_donut(size, weights, colors, bg, thickness, gap_deg, start_deg)


# ------------------------------------------------------------------
# ICONS
# ------------------------------------------------------------------

def _icon_canvas(size, bg):
    return Canvas(size, size, base=hex_rgb(bg)), Canvas.new_layer(size, size)


def render_icon(kind, size, bg="#030C18", color=(58, 160, 255)):
    cv, ly = _icon_canvas(size, bg)
    d = ImageDraw.Draw(ly)
    S = size * SS
    col = (*color, 255)
    lw = max(2, int(S * 0.045))

    if kind == "laptop":
        d.rounded_rectangle([S * 0.16, S * 0.18, S * 0.84, S * 0.62], radius=S * 0.04, outline=col, width=lw)
        d.rounded_rectangle([S * 0.22, S * 0.24, S * 0.78, S * 0.56], radius=S * 0.02, outline=(*color, 120), width=max(1, lw // 2))
        d.polygon([(S * 0.08, S * 0.72), (S * 0.92, S * 0.72), (S * 0.86, S * 0.64), (S * 0.14, S * 0.64)], outline=col)
        d.line([(S * 0.08, S * 0.72), (S * 0.92, S * 0.72), (S * 0.86, S * 0.64), (S * 0.14, S * 0.64), (S * 0.08, S * 0.72)],
               fill=col, width=lw, joint="curve")
        d.line([(S * 0.42, S * 0.68), (S * 0.58, S * 0.68)], fill=col, width=lw)
    elif kind == "cloud":
        # cloud outline as a union of arcs
        d.arc([S * 0.16, S * 0.44, S * 0.52, S * 0.80], 90, 270, fill=col, width=lw)
        d.arc([S * 0.30, S * 0.20, S * 0.70, S * 0.62], 180, 360, fill=col, width=lw)
        d.arc([S * 0.54, S * 0.36, S * 0.86, S * 0.80], 270, 450, fill=col, width=lw)
        d.line([(S * 0.34, S * 0.80), (S * 0.70, S * 0.80)], fill=col, width=lw)
        d.ellipse([S * 0.45, S * 0.52, S * 0.55, S * 0.62], fill=col)
    else:  # network
        nodes = [(0.5, 0.5), (0.5, 0.15), (0.80, 0.34), (0.80, 0.66), (0.5, 0.85), (0.20, 0.66), (0.20, 0.34)]
        for x, y in nodes[1:]:
            d.line([(S * 0.5, S * 0.5), (S * x, S * y)], fill=col, width=lw)
        for i, (x, y) in enumerate(nodes):
            r = S * (0.09 if i == 0 else 0.06)
            d.ellipse([S * x - r, S * y - r, S * x + r, S * y + r], fill=(4, 24, 56, 255), outline=col, width=lw)
    cv.add(ly, 1.0, glow=[(size * 0.04, 0.8), (size * 0.10, 0.5)])
    return cv.image()


def render_ring_icon(size, pct, glyph, c1="#22D07A", c2="#2A8CFF", bg="#030C18"):
    cv = Canvas(size, size, base=hex_rgb(bg))
    ly = Canvas.new_layer(size, size)
    d = ImageDraw.Draw(ly)
    S = size * SS
    c = S / 2
    R = S * 0.43
    wdt = int(S * 0.085)
    d.ellipse([c - R, c - R, c + R, c + R], outline=(18, 50, 82, 255), width=wdt)
    n = 60
    for i in range(n):
        t0 = i / n
        if t0 > pct:
            break
        col = mix(c1, c2, t0 / max(pct, 1e-3))
        d.arc([c - R, c - R, c + R, c + R], -90 + 360 * t0, -90 + 360 * min(pct, t0 + 1.4 / n),
              fill=(*col, 255), width=wdt)
    cv.add(ly, 1.0, glow=[(size * 0.04, 0.7)])

    gl = Canvas.new_layer(size, size)
    g = ImageDraw.Draw(gl)
    col = (200, 230, 255, 255)
    lw = max(2, int(S * 0.04))
    if glyph == "shield":
        pts = [(c, S * 0.28), (S * 0.66, S * 0.38), (S * 0.66, S * 0.55), (c, S * 0.74), (S * 0.34, S * 0.55), (S * 0.34, S * 0.38)]
        g.line(pts + [pts[0]], fill=col, width=lw, joint="curve")
        g.line([(S * 0.43, S * 0.50), (S * 0.48, S * 0.56), (S * 0.58, S * 0.43)], fill=col, width=lw, joint="curve")
    elif glyph == "lock":
        g.rounded_rectangle([S * 0.36, S * 0.47, S * 0.64, S * 0.70], radius=S * 0.03, outline=col, width=lw)
        g.arc([S * 0.41, S * 0.29, S * 0.59, S * 0.55], 180, 360, fill=col, width=lw)
        g.ellipse([c - S * 0.025, S * 0.55, c + S * 0.025, S * 0.60], fill=col)
    elif glyph == "stars":
        for k in range(12):
            a = k / 12 * math.tau
            x, y = c + math.cos(a) * S * 0.20, c + math.sin(a) * S * 0.20
            rr = S * 0.022
            g.ellipse([x - rr, y - rr, x + rr, y + rr], fill=col)
        g.ellipse([c - S * 0.07, c - S * 0.07, c + S * 0.07, c + S * 0.07], outline=col, width=max(1, lw // 2))
    else:  # cross
        t = S * 0.07
        g.rounded_rectangle([c - t, S * 0.30, c + t, S * 0.70], radius=S * 0.02, outline=col, width=lw)
        g.rounded_rectangle([S * 0.30, c - t, S * 0.70, c + t], radius=S * 0.02, outline=col, width=lw)
    cv.add(gl, 1.0, glow=[(size * 0.03, 0.5)])
    return cv.image()


# ------------------------------------------------------------------
# BRAIN
# ------------------------------------------------------------------

def _brain_outline():
    pts = [
        (0.08, 0.50), (0.09, 0.40), (0.14, 0.30), (0.22, 0.20), (0.33, 0.12), (0.46, 0.08), (0.60, 0.09),
        (0.73, 0.14), (0.84, 0.23), (0.91, 0.34), (0.93, 0.46), (0.90, 0.58), (0.84, 0.66), (0.76, 0.70),
        (0.74, 0.78), (0.68, 0.86), (0.60, 0.88), (0.54, 0.84), (0.52, 0.93), (0.47, 0.97), (0.44, 0.88),
        (0.42, 0.74), (0.34, 0.72), (0.26, 0.70), (0.19, 0.64), (0.12, 0.58),
    ]
    # Chaikin smoothing
    for _ in range(3):
        new = []
        for i in range(len(pts)):
            p, q = pts[i], pts[(i + 1) % len(pts)]
            new.append((0.75 * p[0] + 0.25 * q[0], 0.75 * p[1] + 0.25 * q[1]))
            new.append((0.25 * p[0] + 0.75 * q[0], 0.25 * p[1] + 0.75 * q[1]))
        pts = new
    return pts


def render_brain(w, h, bg="#030C18"):
    w, h = max(int(w), 40), max(int(h), 40)
    cv = Canvas(w, h, base=hex_rgb(bg))
    outline = [(x * w, y * h) for x, y in _brain_outline()]

    # clip mask
    mask = Image.new("L", (w * SS, h * SS), 0)
    ImageDraw.Draw(mask).polygon([(x * SS, y * SS) for x, y in outline], fill=255)

    rnd = random.Random(11)
    folds = Image.new("RGBA", (w * SS, h * SS), (0, 0, 0, 0))
    fd = ImageDraw.Draw(folds)
    # gyri: wavy lines that follow concentric contours
    for k in range(26):
        t = 0.10 + k * 0.034
        pts = []
        for i in range(90):
            a = i / 89 * math.pi * 1.25 + math.pi * 0.95
            rx = (0.40 - t * 0.38) * w + 0.012 * w * math.sin(i * 0.9 + k)
            ry = (0.34 - t * 0.32) * h + 0.014 * h * math.cos(i * 0.8 + k * 1.3)
            pts.append(((0.50 + 0.0) * w + math.cos(a) * rx * 1.12, 0.45 * h + math.sin(a) * ry * 1.25))
        al = int(110 + 120 * rnd.random())
        fd.line([(x * SS, y * SS) for x, y in pts], fill=(70, 170, 255, al), width=int(0.9 * SS), joint="curve")
    # central & lateral sulci
    for pts in (
        [(0.50, 0.12), (0.52, 0.26), (0.47, 0.40), (0.50, 0.52)],
        [(0.18, 0.56), (0.32, 0.54), (0.46, 0.60), (0.60, 0.58), (0.74, 0.62)],
        [(0.62, 0.14), (0.66, 0.30), (0.72, 0.44), (0.80, 0.52)],
    ):
        fd.line([(x * w * SS, y * h * SS) for x, y in pts], fill=(110, 200, 255, 230), width=int(1.4 * SS), joint="curve")
    folds_np = Image.new("RGBA", folds.size, (0, 0, 0, 0))
    folds_np.paste(folds, (0, 0), mask)

    out = Canvas.new_layer(w, h)
    od = ImageDraw.Draw(out)
    sp = [(x * SS, y * SS) for x, y in outline]
    od.line(sp + [sp[0]], fill=(120, 205, 255, 255), width=int(1.8 * SS), joint="curve")

    # neural nodes + links
    nodes = []
    mk = mask.resize((w, h), Image.BILINEAR)
    mk_np = np.asarray(mk)
    while len(nodes) < 46:
        x, y = rnd.uniform(0.1, 0.92), rnd.uniform(0.1, 0.92)
        if mk_np[int(y * (h - 1)), int(x * (w - 1))] > 200:
            nodes.append((x * w, y * h))
    for i, a in enumerate(nodes):
        for b in nodes[i + 1:]:
            if math.hypot(a[0] - b[0], a[1] - b[1]) < w * 0.14:
                od.line([(a[0] * SS, a[1] * SS), (b[0] * SS, b[1] * SS)], fill=(60, 150, 255, 120), width=max(1, SS // 2))
    for x, y in nodes:
        rr = 1.7 * SS
        od.ellipse([x * SS - rr, y * SS - rr, x * SS + rr, y * SS + rr], fill=(170, 225, 255, 255))

    cv.add(folds_np, 0.9, glow=[(1.5, 0.5)])
    cv.add(out, 1.0, glow=[(2.5, 0.9), (8, 0.55)])
    return cv.image()


# ------------------------------------------------------------------
# LOGO / HEADER ICONS
# ------------------------------------------------------------------

def render_logo(size, bg="#010510"):
    cv = Canvas(size, size, base=hex_rgb(bg))
    ly = Canvas.new_layer(size, size)
    d = ImageDraw.Draw(ly)
    S = size * SS
    pts = [(S * 0.5, S * 0.06), (S * 0.88, S * 0.2), (S * 0.88, S * 0.55), (S * 0.5, S * 0.95),
           (S * 0.12, S * 0.55), (S * 0.12, S * 0.2)]
    d.polygon(pts, fill=(8, 36, 80, 255))
    d.line(pts + [pts[0]], fill=(90, 190, 255, 255), width=int(S * 0.055), joint="curve")
    cv.add(ly, 1.0, glow=[(size * 0.04, 0.9), (size * 0.12, 0.5)])
    tx = Canvas.new_layer(size, size)
    td = ImageDraw.Draw(tx)
    f = _font(S * 0.36)
    box = td.textbbox((0, 0), "AI", font=f)
    td.text((S * 0.5 - (box[2] - box[0]) / 2 - box[0], S * 0.50 - (box[3] - box[1]) / 2 - box[1]), "AI",
            font=f, fill=(255, 255, 255, 255))
    cv.add(tx, 1.0, over=True)
    return cv.raw_image()


def render_bell(size, bg="#010510"):
    cv = Canvas(size, size, base=hex_rgb(bg))
    ly = Canvas.new_layer(size, size)
    d = ImageDraw.Draw(ly)
    S = size * SS
    col = (150, 175, 205, 255)
    lw = max(2, int(S * 0.055))
    d.arc([S * 0.25, S * 0.18, S * 0.75, S * 0.62], 180, 360, fill=col, width=lw)
    d.line([(S * 0.25, S * 0.40), (S * 0.22, S * 0.66), (S * 0.14, S * 0.74)], fill=col, width=lw, joint="curve")
    d.line([(S * 0.75, S * 0.40), (S * 0.78, S * 0.66), (S * 0.86, S * 0.74)], fill=col, width=lw, joint="curve")
    d.line([(S * 0.14, S * 0.74), (S * 0.86, S * 0.74)], fill=col, width=lw)
    d.arc([S * 0.42, S * 0.70, S * 0.58, S * 0.90], 0, 180, fill=col, width=lw)
    d.ellipse([S * 0.66, S * 0.08, S * 0.86, S * 0.28], fill=(255, 50, 70, 255))
    cv.add(ly, 1.0, over=True)
    return cv.raw_image()


def render_gear(size, bg="#010510"):
    cv = Canvas(size, size, base=hex_rgb(bg))
    ly = Canvas.new_layer(size, size)
    d = ImageDraw.Draw(ly)
    S = size * SS
    c = S / 2
    col = (150, 175, 205, 255)
    lw = max(2, int(S * 0.05))
    pts = []
    teeth = 8
    for i in range(teeth * 4):
        a = i / (teeth * 4) * math.tau
        rad = S * (0.40 if (i // 2) % 2 == 0 else 0.30)
        pts.append((c + math.cos(a) * rad, c + math.sin(a) * rad))
    d.line(pts + [pts[0]], fill=col, width=lw, joint="curve")
    r = S * 0.12
    d.ellipse([c - r, c - r, c + r, c + r], outline=col, width=lw)
    cv.add(ly, 1.0, over=True)
    return cv.raw_image()


# ------------------------------------------------------------------
# SMALL BADGES
# ------------------------------------------------------------------

def render_check(size, bg="#030C18", fill=(23, 136, 79)):
    """Green round badge with a tick (card header)."""
    cv = Canvas(size, size, base=hex_rgb(bg))
    ly = Canvas.new_layer(size, size)
    d = ImageDraw.Draw(ly)
    S = size * SS
    d.ellipse([S * 0.04, S * 0.04, S * 0.96, S * 0.96], fill=(*fill, 255))
    d.line([(S * 0.27, S * 0.52), (S * 0.43, S * 0.68), (S * 0.74, S * 0.34)],
           fill=(255, 255, 255, 255), width=max(2, int(S * 0.10)), joint="curve")
    cv.add(ly, 1.0, over=True)
    return cv.raw_image()


def render_node(size, bg="#030C18", color=(40, 170, 255)):
    """Small ring with a centre dot (engine list bullets)."""
    cv = Canvas(size, size, base=hex_rgb(bg))
    ly = Canvas.new_layer(size, size)
    d = ImageDraw.Draw(ly)
    S = size * SS
    c = S / 2
    r = S * 0.42
    d.ellipse([c - r, c - r, c + r, c + r], outline=(*color, 255), width=max(2, int(S * 0.07)))
    r2 = S * 0.10
    d.ellipse([c - r2, c - r2, c + r2, c + r2], fill=(150, 220, 255, 255))
    cv.add(ly, 1.0, glow=[(size * 0.06, 0.8)])
    return cv.image()
