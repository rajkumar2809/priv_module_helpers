# -*- coding: utf-8 -*-

import os, sys
import json
import subprocess

import cfg_util
from monkey_tools.utils import logger_util

_PYTHON = '/usr/bin/python2.7'
_SCRIPT_NAME = "main.py"
logger = logger_util.get_standard_logger("riskchecker_booter")

def get_data_dir():
	cfg = cfg_util.parse_config()
	gzip_dir = cfg["gzip_dir"]
	logger.debug("get gzip dir:{}".format(gzip_dir))
	return gzip_dir

def get_script_dir():
	_dir = cfg_util.CURR_DIR
	logger.debug("get script dir:{}".format(_dir))
	return _dir

def boot():
	logger.info("boot script:{} python:{}".format(_SCRIPT_NAME, _PYTHON))
	_dir = get_script_dir()
	script = "{}/{}".format(_dir, _SCRIPT_NAME)
	os.chdir(_dir)
	sp=subprocess
	try:
		return sp.call([_PYTHON, script], stderr=sp.STDOUT)
	except sp.CalledProcessError as e:
		logger.error("call script is error. message:{}".format(e.output))
		logger.exception(e)
		return 1

