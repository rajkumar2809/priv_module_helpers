# -*- coding: utf-8 -*-

import os, sys
import json, logging
import subprocess as sp
from base64 import b64encode as enc64, b64decode as dec64

CURR_DIR  = os.path.dirname( os.path.abspath(__file__) )
CONF_DIR  = CURR_DIR+"/config"
CONF_FILE = CONF_DIR+"/config.json"

_DEFAULT_PYTHON = sys.executable
_SCRIPT_DIR  = CURR_DIR+"/bin"
_SCRIPT_CALL_AUTORUN = _SCRIPT_DIR+"/auto_response.py"
logger = logging.getLogger(__name__)
_USER_ = "splunk"

def execute_command(raw_command, exec_user=None):
	user = os.environ.get("USER")
	if user == "root":
		username = exec_user if exec_user else _USER_
		command = [ "sudo", "-u", username ]
		command.extend(raw_command)
	else:
		command = raw_command
	try:
		return sp.check_output(command, stderr=sp.STDOUT)
	except sp.CalledProcessError as e:
		logger.error("call script is error. message:{}".format(e.output))
		logger.exception(e)
		return 1

def boot_autorun(alerts_csv_gz, product,
		exec_user=None, splunk_name=None,  _python=None):
	if _python is None:
		_python = _DEFAULT_PYTHON
	api_type = product
	logger.info("boot script:{} python:{}".format(_SCRIPT_CALL_AUTORUN, _python))
	_dir = _SCRIPT_DIR
	os.chdir(_dir)
	command = [ _python, _SCRIPT_CALL_AUTORUN,
			alerts_csv_gz, '--api_type', api_type ]
	execute_command(command, exec_user)

