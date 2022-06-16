# -*- encoding:utf-8
# TODO:need to make testcode
# TODO:need to be refactor apikey management

import os, sys
import json
from monkey_tools.utils import rest_util as rest
from monkey_tools.utils import time_util as time
from connectors.sophos_api import central_api as api

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
CONF_DIR = CURR_DIR+"/config"
CFG_FILE = CONF_DIR+"/config.json"
STATE_DIR = CURR_DIR+"/state"
STATE_FILE_ALERT = STATE_DIR+"/alert.json"
STATE_FILE_EVENT = STATE_DIR+"/event.json"

with open(CFG_FILE) as f:
	_CONFIG = json.load(f)

def get_events(target):
	if target and target.lower() == "all":
		result = []
		for each in _get_all_customers():
			result.append( get_event(each) )
		return result
	else:
		return get_event(target)

def get_event(customer_name):
	_api = _get_api_module(customer_name) 
	cursor = _get_cursor(customer_name, "event")
	res = _api.get_events(next_cursor=cursor)
	_save_state(customer_name, res["next_cursor"], "event")
	return res

def get_alerts(target):
	if target and target.lower() == "all":
		result = []
		for each in _get_all_customers():
			result.append( get_alert(each) )
		return result
	else:
		return get_alert(target)

def get_alert(customer_name):
	_api = _get_api_module(customer_name) 
	cursor = _get_cursor(customer_name, "alert")
	res = _api.get_alerts(next_cursor=cursor)
	_save_state(customer_name, res["next_cursor"], "alert")
	return res

# private

def _save_state(customer_name, next_cursor, _type):
	state = _get_state_all(_type)
	if not customer_name in state:
		state[customer_name] = {}
	state[customer_name]["next_cursor"] = next_cursor

	state_file = _get_state_file(_type)
	with open(state_file, "w") as wf:
		json.dump(state, wf, indent=4)

def _get_all_customers():
	return _CONFIG["apikey"].keys()

def _get_cursor(customer_name, _type):
	state = _get_state_all(_type)
	if customer_name in state:
		return state[customer_name]["next_cursor"]
	else:
		return None

def _get_state_all(_type):
	state_file = _get_state_file(_type)
	if os.path.exists(state_file):
		with open(state_file) as f:
			state = json.load(f)
		return state
	else:
		return {}

def _get_state_file(_type):
	if _type == "alert":
		return STATE_FILE_ALERT
	else:
		return STATE_FILE_EVENT

def _get_api_module(_customer):
	assert _customer, "dont set customer_name yet"
	creds = _CONFIG["creds"]
	if _customer in creds:
		_cred = creds[_customer]
		return api.SophosCentralApi(**_cred)
	else:
		assert False, "cannot exist customer_name in config"

def _test_alerts():
	customer_name="DGH1"
	res = get_alerts(customer_name)
	print json.dumps(res, indent=4)

def _test_events():
	customer_name="DGH1"
	res = get_events(customer_name)
	print json.dumps(res, indent=4)

def _test():
	_test_alerts()
	_test_events()

if __name__ == "__main__":
	_test()
