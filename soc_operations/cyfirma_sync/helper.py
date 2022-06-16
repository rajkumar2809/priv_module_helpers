# -*- coding: utf-8 -*-

import os, sys
import json, logging
import subprocess

CURR_DIR  = os.path.dirname( os.path.abspath(__file__) )
CONF_DIR  = CURR_DIR+"/config"
CONF_FILE = CONF_DIR+"/config.json"

_PYTHON = sys.executable
_SCRIPT_DIR  = CURR_DIR+"/bin"
_SCRIPT_NAME_RMSYNC = _SCRIPT_DIR+"/pullrminfo2splunk.py"
logger = logging.getLogger(__name__)

def boot_rmsync(product, target, by_file=True, by_local=True):
	logger.info("boot script:{} python:{}".format(_SCRIPT_NAME_RMSYNC, _PYTHON))
	_dir = _SCRIPT_DIR
	os.chdir(_dir)
	sp=subprocess
	command = [ _PYTHON, _SCRIPT_NAME_RMSYNC, product, target ]
	if by_file:
		command.append("--by_file")
	if by_local:
		command.append("--by_local")

	try:
		return sp.check_output(command, stderr=sp.STDOUT)
	except sp.CalledProcessError as e:
		logger.error("call script is error. message:{}".format(e.output))
		logger.exception(e)
		return 1

