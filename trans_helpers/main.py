# -*- coding: utf-8 -*-

import sys, os
import json
from connectors.googletrans_api import trans

PJ_TOP = os.path.dirname( os.path.abspath(__file__) )
_CONF_DIR = PJ_TOP+"/config/"
_CONF_NAME = _CONF_DIR+"trans.json"

def trans_en2ja(msg, key=None, cfg_file=None):
	api = get_api(key)
	return api.en2ja(msg)

def get_api(key=None, cfg_file=None):
	cfg = parse_config(cfg_file)
	if key:
		cfg["key"] = key
	return trans.GoogleTransApi(**cfg)

def parse_config(cfg_file=None):
	if cfg_file is None:
		cfg_file = _CONF_NAME
	with open(cfg_file, "rb") as f:
		cfg = json.load(f)
	return cfg

