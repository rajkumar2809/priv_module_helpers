# -*- coding: utf-8 -*-

import os, sys
import json
import subprocess as sp

from monkey_tools.utils import logger_util

_PYTHON = '/usr/bin/python2.7'
_SCRIPT_NAME = "main.py"
CURR_DIR = os.path.dirname( os.path.abspath(__file__) )

_SERVER = "localhost"
_USER_ = "splunk"

logger = logger_util.get_standard_logger("analystchecker")

def get_script_dir():
	_dir = CURR_DIR
	logger.debug("get script dir:{}".format(_dir))
	return _dir

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

def boot(alerts_csv, exec_user=None, _python=None):
	if _python is None:
		_python = _PYTHON
	logger.info("boot script:{} python:{}".format(_SCRIPT_NAME, _python))
	_dir = get_script_dir()
	script = "{}/{}".format(_dir, _SCRIPT_NAME)
	os.chdir(_dir)
	command = [ _python, script, alerts_csv ]
	command.append('--server')
	command.append(_SERVER)
	return execute_command(command, exec_user)

