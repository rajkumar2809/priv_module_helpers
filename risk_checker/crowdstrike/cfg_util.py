# -*- coding: utf-8 -*-

import os, sys
import json

import cfg_util

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )

_CONF_PATH = CURR_DIR+"/config"
_LOG_CONF = _CONF_PATH+"/log.conf"
_GEN_CONF = _CONF_PATH+"/config.json"

def parse_config(cfg_name=None):
	if cfg_name is None:
		cfg_name = _GEN_CONF
	with open(cfg_name) as f:
		cfg = json.load(f)
	gz_dirname = cfg["gzip_dir"]
	if not cfg["gzip_dir"].endswith("/"):
		gz_dirname += "/"
	if cfg["gzip_dir"].startswith("./"):
		gz_dirname = CURR_DIR+gz_dirname[1::]
	elif cfg["gzip_dir"].startswith("../"):
		gz_dirname = CURR_DIR+"/"+gz_dirname
	cfg["gzip_dir"] = gz_dirname
	return cfg

def get_log_conf():
	return _LOG_CONF

