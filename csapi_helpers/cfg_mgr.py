# -*- coding: utf-8 -*-

import os, sys
import json, logging, time, glob

_CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
_CONF_DIR = _CURR_DIR + "/config"
_OAUTH_CONF = _CONF_DIR+"/oauth.json"
_THREAT_GRAPH_CONF = _CONF_DIR+"/threat_graph.json"

_CREDS_DIR = _CONF_DIR+"/credentials"

def get_oauth_conf():
	with open(_OAUTH_CONF) as f:
		cfg = json.load(f)
	for each in glob.glob(_CREDS_DIR+"/*/oauth.json"):
		try:
			with open(each) as f:
				each_cfg=json.load(f)
			cfg[each_cfg["customer_name"]]=each_cfg["keys"]
		except Exception as e:
			pass
	return cfg

def get_threat_graph_conf():
	with open(_THREAT_GRAPH_CONF) as f:
		cfg = json.load(f)
	for each in glob.glob(_CREDS_DIR+"/*/threat_graph.json"):
		try:
			with open(each) as f:
				each_cfg=json.load(f)
			cfg[each_cfg["customer_name"]]=each_cfg["keys"]
		except Exception as e:
			pass
	return cfg



