# -*- coding: utf-8 -*-

import sys, os, time, json, glob, re
from monkey_tools.utils.str_util import decrypto64 as dec64, encrypto64 as enc64

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )+"/"
PJ_TOP = CURR_DIR+"../"

CONF_PATH = CURR_DIR+"config/"
CONF_NAME = "cbdefense.json"

CREDS_PATH = CONF_PATH+"credentials/"

"""
need to refactor.
merge to app_cfg.py
"""

def parse_all_conf():
	cfg_name = CONF_PATH+CONF_NAME
	with open(cfg_name, "r") as f:
		conf_all = json.load(f)
	for each in glob.glob(CREDS_PATH+"*.json"):
		try:
			with open(each, "r") as f:
				each_cfg = json.load(f)
				conf_all.append(each_cfg)
		except Exception as e:
			pass
	return conf_all

def get_customers():
	conf_all = parse_all_conf()
	return [ each["customer_name"] for each in conf_all ]

def get_conf(customer_info, conf_path=CONF_PATH):
	conf_all = parse_all_conf()
	return _get_customer_conf(conf_all, customer_info)

def _get_customer_conf(conf_all, customer_info):
	pt = r"^[A-Z]{3}$"
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
		elif re.match(pt, customer_info):
			customer_name = each["customer_name"]
			if customer_name.startswith(customer_info):
				tokens = {}
				for k, v in each["tokens"].items():
					if len(v) > 0:
						tokens[k]=dec64(v)
					else:
						tokens[k]=v
				each["tokens"]=tokens
				return each
		elif isinstance(each.get("base_customer_name"), basestring):
			base_customer_name = each.get("base_customer_name")
			if customer_info.startswith(base_customer_name):
				tokens = {}
				for k, v in each["tokens"].items():
					if len(v) > 0:
						tokens[k]=dec64(v)
					else:
						tokens[k]=v
				each["tokens"]=tokens
				return each
	return None

