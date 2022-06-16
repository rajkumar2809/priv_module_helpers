# -*- encoding:utf-8
# TODO:need to make testcode
# TODO:need to be refactor apikey management

import os, sys
import json, time, glob
from connectors.fireeyehx_api import hx_api as api

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
CONF_DIR = CURR_DIR+"/config"
CFG_FILE = CONF_DIR+"/config.json"

CREDS_DIR = CONF_DIR+"/credentials"

with open(CFG_FILE) as f:
	CONFIG = json.load(f)

for each in glob.glob(CREDS_DIR+"/*.json"):
	try:
		with open(each) as f:
			cfg = json.load(f)
		CONFIG["credentials"][cfg["customer_name"]]=cfg["keys"]
	except Exception as e:
		print e
		pass

customer_name = None

def get_hostset(customer_name, hostname, with_case=False, is_fuzzy=False, with_multi=False):
	hostname = hostname if with_case else hostname.lower()
	_api = _get_api(customer_name)
	params = { "limit" : 5000 }
	res = _api.get_hostsets(params=params)
	data = json.load(res).get("data")
	hostsets = []
	if data and "entries" in data:
		_sets = data["entries"]
		for each in _sets:
			set_name = each["name"]
			if set_name.lower() == "all hosts":
				continue
			params = { "limit" : 50000 }
			hosts = _get_hosts(each["_id"], _api, params=params)
			if len(hosts) is not 0:
				for host in hosts:
					name = host["hostname"] if with_case else host["hostname"].lower()
					if is_fuzzy and hostname in name:
						hostsets.append(set_name)
					elif hostname == name:
						hostsets.append(set_name)
	if len(hostsets) is 0:
		hostsets.append("default")
	hostsets = list(set(hostsets))
	if with_multi:
		return ",".join(hostsets)
	else:
		return hostsets[0]

def get_hosts(customer_name, hostset_id, is_simple=True):
	_api = _get_api(customer_name)
	hosts = _get_hosts(hostset_id, _api)
	if is_simple:
		return [ each["hostname"] for each in hosts ]
	else:
		return hosts

def lift_containment(customer_name, agent_id):
	_api = _get_api(customer_name)
	flag = _api.containment_cancel(agent_id)
	return flag

def to_containment(customer_name, agent_id, with_approval=True, interval=15):
	_api = _get_api(customer_name)
	flag = _api.containment_request(agent_id)
	if flag:
		if with_approval:
			time.sleep(interval)
			return _api.containment_approval(agent_id)
		else:
			return True
	else:
		return False

def delete_enterprise_search(customer_name, _id):
	_api = _get_api(customer_name)
	flag = _api.delete_enterprise_search(_id)
	return flag

def get_result_enterprise_search(customer_name, _id=None):
	_api = _get_api(customer_name)
	res = _api.get_result_enterprise_search(_id)
	data = json.load(res)
	if _id:
		stats = data["data"]["stats"]
		result = {  "_id"     : data["data"]["_id"],
					"result"  : stats["search_state"],
					"hosts"   : stats["hosts"],
					"skipped" : stats["skipped_hosts"] }
		return result
	else:
		return data

def set_new_enterprise_search(customer_name, queries):
	_api = _get_api(customer_name)
	res = _api.set_new_enterprise_search(queries)
	data = json.load(res)
	return data["data"]["_id"]

def make_queries_by_hostnames(namelist):
	FIELD_NAME = "DNS Hostname"
	_OP = "equals"
	result = [  _make_each_query_dict(FIELD_NAME, each, _OP)
				for each in namelist ]
	return result

def make_queries_by_ipaddrs(iplist):
	FIELD_NAME = "Remote IP Address"
	_OP = "equals"
	result = [  _make_each_query_dict(FIELD_NAME, each, _OP)
				for each in iplist ]
	return result

def make_queries_by_sha256(hashlist):
	FIELD_NAME = "File SHA256 Hash"
	_OP = "equals"
	result = [  _make_each_query_dict(FIELD_NAME, each, _OP)
				for each in hashlist ]
	return result

def make_queries_by_url(hashlist):
	FIELD_NAME = "URL"
	_OP = "equals"
	result = [  _make_each_query_dict(FIELD_NAME, each, _OP)
				for each in hashlist ]
	return result

def get_customers():
	return CONFIG["credentials"].keys()

# private

def _make_each_query_dict(field_name, value, operator="equals"):
	return {"field": field_name,
			"operator": operator,
			"value": value }

def _get_api(customer_name):
	cfg = _get_creds(customer_name)
	return api.FireeyeHxApi( cfg["appliance"],
			cfg["username"], cfg["password"] )

def _get_hosts(_id, _api, params=None):
	res = _api.get_hosts(_id, params)
	info = json.load(res)
	return info["data"]["entries"]

def _get_creds(customer_name):
	return CONFIG["credentials"][customer_name]

def _test_to_containment():
	aid = 'FlqKYLAgt97evmPMc4Rm0G'
	print to_containment("DGH1", aid)

def _test_hostset(with_multi=True):
	host = "hx09"
	res = get_hostset("DGH2", host, with_case=True, with_multi=with_multi)
	print "{} -> {}".format(host, res)
	host = "HX09"
	res = get_hostset("DGH2", host, with_case=True, with_multi=with_multi)
	print "{} -> {}".format(host, res)

def _test_get_epsearch():
	_id = 25
	res = get_result_enterprise_search("DGH2", _id)
	print json.dumps(res, indent=4)

def _test_delete_epsearch():
	_id = 31
	flag = delete_enterprise_search("DGH2", _id)
	print flag

def _test_add_epsearch():
	values = [
			"https://yahoo.co.jp",
			"https://test.co.jp",
			"https://google.com"
	]
	queries = make_queries_by_url(values)
	res = set_new_enterprise_search("DGH2", queries)
	print res

if __name__ == '__main__':
	_test_hostset(False)

