# -*- coding: utf-8 -*-

import os, sys
import json, re, glob, sre_constants

BLACK = -1
WHITE = 1
GRAY  = 0

TYPECODE_INDICATOR = 1
TYPECODE_GENERAL = 2
TYPECODE_MALWARE = 3
TYPECODE_EXPLOIT = 4
TYPECODE_NOISE   = 9

