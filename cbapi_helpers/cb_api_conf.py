# -*- coding: utf-8 -*-

import sys, os, time, json
from monkey_tools.utils.str_util import decrypto64 as dec64, encrypto64 as enc64

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )+"/"
PJ_TOP = CURR_DIR+"../"

CONF_PATH = CURR_DIR+"config/"
CONF_NAME = "cbdefense.json"

"""
need to refactor.
merge to app_cfg.py
"""

def get_customers():
	cfg_name = CONF_PATH+CONF_NAME
	with open(cfg_name, "r") as f:
		conf_all = json.load(f)
	return [ each["customer_name"] for each in conf_all ]

def get_conf(customer_info, conf_path=CONF_PATH):
	cfg_name = CONF_PATH+CONF_NAME
	with open(cfg_name, "r") as f:
		conf_all = json.load(f)
	return _get_customer_conf(conf_all, customer_info)

def _get_customer_conf(conf_all, customer_info):
	for each in conf_all:
		if (each["customer_name"] == customer_info or 
			each["customer_id"]   == customer_info ):
			tokens = {}
			for k, v in each["tokens"].items():
				if len(v) > 0:
					tokens[k]=dec64(v)
				else:
					tokens[k]=v
			each["tokens"]=tokens
			return each
	return None

