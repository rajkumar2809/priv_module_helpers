# -*- encoding:utf-8
# TODO:need to make testcode

import os, sys
import json
from connectors.cyfirma_api import cyfirma_api as _api

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
CONF_DIR = CURR_DIR+"/config"
CFG_FILE = CONF_DIR+"/config.json"

with open(CFG_FILE) as f:
	CONFIG = json.load(f)

def get_ioc_by_json(by_raw=False, by_diff=True, by_all=True):
	key = _get_key()
	api = _api.CyfirmaAPI(key, "json")
	if by_diff:
		result = api.get_diff(by_all)
	else:
		result = api.get_current(by_all)
	if by_raw:
		return result
	else:
		return grep_ioc(result)
	

def grep_ioc(rawdata):
	return rawdata["indicators"]["indicators"]

# private

def _get_key():
	key = CONFIG["key"]
	return key.strip()

def __example__():
	iocs = get_ioc_by_json(by_diff=False)
	print len(iocs)
	print json.dumps(iocs[0], indent=4)

if __name__ == "__main__":
	__example__()
