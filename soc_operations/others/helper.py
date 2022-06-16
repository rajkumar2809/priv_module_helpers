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
_SCRIPT_CALL_IVR = _SCRIPT_DIR+"/call_ivr.py"
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

def boot_autorun(customer_name, product,
		alert_id, severity, alert_datetime, ticket_no,
		alert_type=None, device_name=None, policy=None, device_id=None,
		with_base64=False, exec_user=None, splunk_name=None,  _python=None):
	if _python is None:
		_python = _DEFAULT_PYTHON
	if customer_name.startswith("NSL"):
		api_type = "nssol"
	elif product == "cbdefense" or product == "fireeye_nx":
		api_type = product
	elif product == "stellar":
		api_type = product
	else:
		api_type = "call_ivr"
	logger.info("boot script:{} python:{}".format(_SCRIPT_CALL_AUTORUN, _python))
	_dir = _SCRIPT_DIR
	os.chdir(_dir)
	command = [ _python, _SCRIPT_CALL_AUTORUN, customer_name, '--api_type', api_type ]
	if splunk_name:
		command.append("-n")
		command.append(splunk_name)
	if not api_type == "call_ivr":
		command.append("-d")
		command.append( make_args(
			alert_id=alert_id, 
			severity=severity, 
			alert_datetime=alert_datetime,
			ticket_no=ticket_no,
			alert_type=alert_type, 
			device_name=device_name,
			policy=policy,
			device_id=device_id,
			product=product,
			with_base64=with_base64) )
		if with_base64:
			command.append("-b")
	return execute_command(command, exec_user)

def make_args(alert_id, severity, alert_datetime, ticket_no, 
		alert_type=None, device_name=None, policy=None,
		device_id=None, product=None, with_base64=False):
	result = {  "alert_id"   : alert_id,
				"severity"   : severity,
				"alert_datetime" : alert_datetime,
				"ticket_no"  : ticket_no }
	if alert_type:
		result["alert_type"] = alert_type
	if device_name:
		result["device_name"] = device_name
	if policy:
		result["policy"] = policy
	if device_id:
		result["device_id"] = device_id
	if product:
		result["product"] = product
	data = json.dumps(result)
	if with_base64:
		return enc64(data)
	else:
		return data

def boot_call_ivr(customer_name, exec_user=None, splunk_name=None, _python=None):
	if _python is None:
		_python = _DEFAULT_PYTHON
	#logger.info("boot script:{} python:{}".format(_SCRIPT_CALL_IVR, _python))
	logger.info("boot script:{} python:{}".format(_SCRIPT_CALL_AUTORUN, _python))
	_dir = _SCRIPT_DIR
	os.chdir(_dir)
	#command = [ _python, _SCRIPT_CALL_IVR, customer_name ]
	command = [ _python, _SCRIPT_CALL_AUTORUN, customer_name, '--api_type', "call_ivr" ]
	if splunk_name:
		command.append("-n")
		command.append(splunk_name)
	return execute_command(command, exec_user)

