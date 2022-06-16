# -*- coding: utf-8 -*-

import os, sys
import json, logging
import subprocess as sp

dirpath = os.path.dirname( os.path.abspath(__file__) )
_CONF_PATH = dirpath+"/config"
_COMF_FILE = _CONF_PATH+"/splunk-commands.json"

with open(_COMF_FILE) as f:
	cfg = json.load(f)

_USER_ = "splunk"

def execute_command(raw_command, exec_user=None):
	user = os.environ.get("USER")
	if user == "root":
		username = exec_user if exec_user else _USER_
		#command = [ "sudo", "-u", username ]
		#command.extend(raw_command)
		command = raw_command
	else:
		command = raw_command
	return sp.check_output(command, stderr=sp.STDOUT)
#	try:
#	except sp.CalledProcessError as e:
#		logger.error("call script is error. message:{}".format(e.output))
#		logger.exception(e)
#		return 1

def add_oneshot(file_name, index, sourcetype, source,
		auth_user=cfg["auth_username"], auth_pass=cfg["auth_password"],
		_binary=cfg["command_binary"], exec_user=None):
	auth = "{}:{}".format(auth_user, auth_pass)
	com = [ _binary, 'add', 'oneshot', file_name,
			'-index', index, '-sourcetype', sourcetype,
			'-rename-source', source, '-auth', auth ]
	execute_command(com, exec_user)

