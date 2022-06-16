# -*- coding: utf-8 -*-

import os, sys
import json
import subprocess

from monkey_tools.utils import logger_util

_PYTHON = '/usr/bin/python2.7'
_SCRIPT_NAME = "commands.py"
logger = logger_util.get_standard_logger("ioc_checker_booter")

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )

def get_script_dir():
	_dir = CURR_DIR+"/bin"
	logger.debug("get script dir:{}".format(_dir))
	return _dir

def boot(product, customers):
	logger.info("boot script:{} python:{}".format(_SCRIPT_NAME, _PYTHON))
	_dir = get_script_dir()
	script = "{}/{}".format(_dir, _SCRIPT_NAME)
	os.chdir(_dir)
	sp=subprocess
	logger.info("boot script with:{}".format(str([_PYTHON, script, product, "--c", customers])))
	try:
		return sp.check_output([_PYTHON, script, product, "--c", customers], stderr=sp.STDOUT)
	except sp.CalledProcessError as e:
		logger.error("call script is error. message:{}".format(e.output))
		logger.exception(e)
		return 1

