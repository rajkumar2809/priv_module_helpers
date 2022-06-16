# -*- coding: utf-8 -*-

import os, sys
import json, re, glob, sre_constants

BLACK = -1
WHITE = 1
GRAY  = 0

TYPECODE_GENERAL = 1
TYPECODE_RANSOM  = 2
TYPECODE_MALWARE = 3
TYPECODE_HIDDEN  = 4
TYPECODE_BLACKLIST = 5
TYPECODE_NOISE   = 9

