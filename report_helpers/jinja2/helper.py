# -*- encoding:utf-8 -*-

import os, sys
import subprocess

_PYTHON_ = '/usr/bin/python'
CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
_SCRIPT_NAME = "bin/commands.py"

_mac_test_python = '/usr/local/bin/python'

def analyst_report(data, _b64=False, _file=False, _python=None):
	if _python is None:
		_python = _PYTHON_
	script = "{}/{}".format(CURR_DIR, _SCRIPT_NAME)
	com = [_python, script,
		"-t", "analyst", "--subtype", "helix:squid", "-d", data ]
	if _b64:
		com.append( "-b" )
	if _file:
		com.append( "-if" )
	return subprocess.check_output(com)

def write_analyst_report(data, filename, _b64=False, _file=False, _pdf=True, _python=None):
	if _python is None:
		_python = _PYTHON_
	script = "{}/{}".format(CURR_DIR, _SCRIPT_NAME)
	com = [_python, script,
		"-t", "analyst", "--subtype", "helix:squid", "-d", data,
		"-o", filename ]
	if _b64:
		com.append( "-b" )
	if _file:
		com.append( "-if" )
	if _pdf:
		com.append( "-p" )
	return subprocess.call(com)


