# -*- coding: utf-8 -*-

import os, sys
import json, logging, time

import oauth_api_base as _base
import cfg_mgr

from connectors.crowdstrike_api import oauth_api as csapi
from connectors.crowdstrike_api import threat_graph_api as tgapi
from monkey_tools.utils import time_util

_CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
_CONF_DIR = _CURR_DIR + "/config"
_TOKEN_DIR  = _CURR_DIR+"/token"
_OAUTH_CONF = _CONF_DIR+"/oauth.json"

logger = logging.getLogger()

_SUPPORTED_IOCs = ['md5', 'sha256', 'ipv4', 'domain']

def get_customers():
	cfg = cfg_mgr.get_oauth_conf()
	return cfg.keys()

def get_process_graph_idlist(alert):
	info = alert["resources"][0]
	info["detected_behaviors_num"] = len(info["behaviors"])
	result = []
	for each in info["behaviors"]:
		process_id = each.get("triggering_process_graph_id")
		if process_id:
			result.append(process_id)
		parent_id  = each.get("parent_process_graph_id")
		if parent_id:
			result.append(parent_id)
	return list(set(result))

def to_summarize_alert(alert):
	info = alert["resources"][0]
	info["detected_behaviors_num"] = len(info["behaviors"])
	result = []
	for each in info["behaviors"]:
		each_result = {
			"process_graph_id" : each.get("triggering_process_graph_id"),
			"control_graph_id" : each.get("control_graph_id"),
			"tactic"     : each.get("tactic"),
			"objective"  : each.get("objective"),
			"technique"  : each.get("technique"),
			"scenario"   : each.get("scenario"),
			"severity"   : each.get("severity"),
			"confidence" : each.get("confidence") }
		parent = each.get("parent_details")
		if parent:
			each_result["parent_graph_id"] = parent["parent_process_graph_id"]
		result.append(each_result)
	info["behaviors"] = result
	return info

class CSApiHelper(_base.CSOAuthApiHelperBase):
	_API_TYPE_KEY_ = "rest"

	def get_alert(self, alert_id):
		return self._api_get_alert_info(alert_id)

	def get_group_names(self, device_id):
		idlist = self._api_get_group_idlist(device_id)
		if len(idlist) is 0:
			return []
		else:
			return self._api_get_group_name(idlist)
	
	def get_group_name_by_gid(self, group_idlist):
			return self._api_get_group_name(group_idlist)
	
	def get_device_metalists(self, device_id, flag_group=True, flag_tag=True):
		info = self._api_get_device_details(device_id)
		groups = []
		if flag_group:
			for each in info["resources"]:
				if each.has_key("groups"):
					groups.extend( each["groups"] )
		tags = []
		if flag_tag:
			for each in info["resources"]:
				if each.has_key("tags"):
					tags.extend( each["tags"] )
		return { "tags" : tags, "groups" : groups }
	
	def containment_host(self, device_id, to_contain=True):
		if to_contain:
			res = self._api_device_action_v2(device_id, "contain")
		else:
			res = self._api_device_action_v2(device_id, "lift_containment")
		if "errors" in res:
			return len(res["errors"]) is 0
		else:
			return False
	
	def search_devices_by_ioc(self, ioc_type, ioc_value, limit=None):
		assert ioc_type in _SUPPORTED_IOCs, "unsupported ioc type:{}".format(ioc_type)
		try:
			res = self._api_get_devices_by_ioc(ioc_type, ioc_value, limit)
			if res and 'resources' in res:
				return res["resources"]
		except IOError as e:
			if e.getcode() == 404:
				return []
	
	def reputation_sha256(self, value, op="search",
			list_type="BLACK_LIST", filename="unknown"):
		op = op.lower()
		assert op in ("add", "delete", "search"), "op accept only add,delete,search"
		today = time_util.get_date(time_util.YMDHMS)
		if op == "add":
			list_type = list_type.upper()
			assert list_type in ("WHITE_LIST", "BLACK_LIST"), "list type accept only WHITE_LIST or BLACK_LIST"
			data={
				"comment": "MDR Service {}".format(today),
				"indicators" : [ {
					"description": "MDR Service {}".format(today),
					"metadata" : { "filename" : filename },
					"applied_globally" : True,
					"platforms" : [
						"windows",
						"mac",
						"linux"
					],
					"source" : "mdr_service",
					"tags"   : [ list_type ],
					"type"   : "sha256",
					"value"  : value
				} ]
			}
			if list_type == "BLACK_LIST":
				data["indicators"][0]["action"] = "prevent"
				data["indicators"][0]["mobile_action"] = "prevent"
				data["indicators"][0]["severity"] = "high"
			else:
				data["indicators"][0]["action"] = "allow"
				data["indicators"][0]["mobile_action"] = "allow"
			return self._api_reputation_add(data)
		elif op == "delete":
			return self._api_reputation_delete(value)
		else:
			return self._api_reputation_search(value)

	# private
	@_base.dec_api_access
	def _api_reputation_add(self, data):
		return self.api.reputation_add(data)

	@_base.dec_api_access
	def _api_reputation_search(self, sha256):
		return self.api.reputation_search(sha256)

	@_base.dec_api_access
	def _api_reputation_delete(self, sha256):
		return self.api.reputation_delete(sha256)

	@_base.dec_api_access
	def _api_get_devices_by_ioc(self, ioc_type, ioc_value, limit=None):
		return self.api.get_devices_by_ioc(ioc_type, ioc_value, limit)

	@_base.dec_api_access
	def _api_device_action_v2(self, device_id, action):
		return self.api.device_action_v2(device_id, action)

	@_base.dec_api_access
	def _api_get_alert_info(self, alert_id):
		return self.api.get_alert_info(alert_id)

	@_base.dec_api_access
	def _api_get_group_idlist(self, device_id):
		return self.api.get_group_idlist(device_id)

	@_base.dec_api_access
	def _api_get_device_details(self, device_id):
		return self.api.get_device_details(device_id)

	@_base.dec_api_access
	def _api_get_group_name(self, idlist):
		return self.api.get_group_name(idlist)

class CSApiHelper4LiveResponse(_base.CSOAuthApiHelperBase):
	_API_TYPE_KEY_ = "liveresponse"
	_LR_CONFIG = _CONF_DIR+"/liveresponse.json"

	def __init__(self, customer_name):
		super(CSApiHelper4LiveResponse, self).__init__(customer_name)
		self.session_id = None
		self.device_id = None
		self.lr_config = self._parse_liveresponse_config(customer_name)

	def make_session(self, device_id):
		res = self._api_get_session_id(device_id)
		self.device_id = device_id
		try:
			self.session_id = res["resources"][0]["session_id"]
		except Exception as e:
			logger.error("error occurred with < {} >".format(str(res)))
			logger.exception(e)
			raise e
	
	def send_containment_message(self, device_id, script=None):
		self.make_session(device_id)
		if script is None:
			script = self.lr_config["scripts"]["send_containment_message"]
		command = 'runscript -CloudFile="{}"'.format(script)
		com_id = self.send_command(command)
		for i in range(0, 3):
			time.sleep(5)
			flag = self.check_command_result(com_id)
			if flag:
				return True
		return False

	def send_command(self, command): 
		assert self.session_id, "session is not initiated. pelase call make_session at first."
		res = self._api_send_command(command)
		try:
			return res["resources"][0]["cloud_request_id"]
		except Exception as e:
			logger.error("error occurred with < {} >".format(str(res)))
			logger.exception(e)
			raise e

	def check_command_result(self, command_id):
		res = self._api_check_command_result(command_id)
		return res["resources"][0]["complete"]

	# private

	@_base.dec_api_access
	def _api_get_session_id(self, device_id):
		return self.api.get_session_id(device_id)

	@_base.dec_api_access
	def _api_send_command(self, command):
		return self.api.send_command(
				self.session_id, self.device_id, command)

	@_base.dec_api_access
	def _api_check_command_result(self, command_id):
		return self.api.check_command_result(command_id)

	def _parse_liveresponse_config(self, customer_name):
		with open(self._LR_CONFIG) as f:
			cfg = json.load(f)
		return cfg

class ThreatGraphApiHelper(object):
	#_CONFIG_FILE = _CONF_DIR + "/threat_graph.json"
	def __init__(self, customer_name):
		self.customer_name = customer_name
		self.username, self.password = self._get_credential(customer_name)
		self.api_host = self._get_api_host(customer_name)
		self.api = tgapi.CSThreatGraphApi(self.username, self.password, host=self.api_host)

	def get_process_graph(self, process_graph_id):
		res = self.api.get_process_graph(process_graph_id)
		return json.load(res)

	def grep_all_edges(self, ps_graphs):
		resources = ps_graphs.get("resources")
		if resources and len(resources) is not 0:
			return [ self.grep_edge_info(each) 
					for each in resources ]
		else:
			return []
	
	def grep_edge_info(self, ps_graph):
		result = { "id" : ps_graph["id"] }
		edges = ps_graph["edges"]
		result["ipaddr"] = self._grep_psgraph_by_ipaddr(edges)
		result["dns"]    = self._grep_psgraph_by_dns(edges)
		result["file"]   = self._grep_psgraph_by_file(edges)
		result["module"] = self._grep_psgraph_by_module(edges)
		return result

	# private

	def _grep_psgraph_by_module(self, edges):
		result = []
		section_name = "module"
		if section_name in edges:
			for _module in edges[section_name]:
				file_name = _module["properties"].get("ImageFileName")
				if file_name:
					result.append( file_name )
				file_name = _module["properties"].get("TargetFileName")
				if file_name:
					result.append( file_name )
		return result

	def _grep_psgraph_by_file(self, edges):
		result = []
		section_name = "FileOpenInfo"
		if section_name in edges:
			for _module in edges[section_name]:
				info = _module["properties"].get("TargetFileName")
				result.append( info )
		return result

	def _grep_psgraph_by_ipaddr(self, edges):
		result = []
		section_name = "ipv4"
		if section_name in edges:
			for _ipv4 in edges[section_name]:
				addr =  "{}:{}".format(
						_ipv4["properties"].get("RemoteAddressIP4"), 
						_ipv4["properties"].get("RemotePort") )
				result.append( addr )
		return result

	def _grep_psgraph_by_dns(self, edges):
		result = []
		section_name = "dns"
		if section_name in edges:
			for _dns in edges[section_name]:
				result.append( _dns["properties"].get("DomainName") )
		return result

	def _get_credential(self, customer_name):
		creds = self._get_config(customer_name)
		return creds["username"], creds["password"]

	def _get_api_host(self, customer_name):
		cfg = cfg_mgr.get_threat_graph_conf()
		if customer_name in cfg:
			return cfg[customer_name].get("host")
		else:
			raise ValueError("has no config for {}".format(customer_name))

	def _get_config(self, customer_name):
		cfg = cfg_mgr.get_threat_graph_conf()
		if customer_name is None:
			return cfg
		elif customer_name in cfg:
			return cfg[customer_name]
		else:
			raise ValueError("has no config for {}".format(customer_name))

def __get_lrapi__(with_group=True):
	customer_name = "DGH1"
	return CSApiHelper4LiveResponse(customer_name)

def _test_csapi_meta_():
	customer_name = "DGH1"
	device_id = "299aab0ea3724c58b7f86b0dedddc140"
	#device_id = "5ac34d95a58146328f2b11618f1899c4"
	api = CSApiHelper(customer_name)
	metalists = api.get_device_metalists(device_id)
	print json.dumps(metalists, indent=4)

def _test_csapi_alert_(with_group=True):
	customer_name = "DGH1"
	#customer_name = "SNB1"
	api = CSApiHelper(customer_name)
	for alert_id in [
			"ldt:7882ab5814d7421ba7e3f4db46d86e37:103079738842",
			#"ldt:e06c8606235c4f339705aa77e3c2a3bc:25770424020"
		]:
		alert = api.get_alert(alert_id)
		info  = to_summarize_alert(alert)
		if with_group:
			device_id = info["device"]["device_id"]
			group = api.get_group_names(device_id)
			info["device"]["groups"] = group
		print json.dumps(info, indent=4)

def _test_get_oauth_api(customer_name=None):
	if customer_name is None:
		customer_name = 'DGH1'
	return CSApiHelper(customer_name)

def _test_get_api(customer_name=None):
	#customer_name = 'PIS1'
	if customer_name is None:
		customer_name = 'DGH1'
	return ThreatGraphApiHelper(customer_name)

def _test_get_ps_graph(_id):
	api = _test_get_api()
	res = api.get_process_graph(_id)
	return res

def _test_get_ps_graph_edge(_id, with_grep=True, customer_name=None):
	api = _test_get_api(customer_name)
	res = api.get_process_graph(_id)
	if with_grep:
		return api.grep_all_edges(res)
	else:
		return res

def _test_containment(to_contain):
	api = _test_get_oauth_api()
	device_id = "299aab0ea3724c58b7f86b0dedddc140"
	is_success = api.containment_host(device_id, to_contain)
	print is_success

def _test_tgapi_():
	#_id = 'pid:75a6e0272f7840e36cd70244badfbd75:73053730815'
	#_id = 'pid:789cb7bb401942d2b552a32b0f2b3407:26051428826' # for DGH
	_id = 'pid:e06c8606235c4f339705aa77e3c2a3bc:27021817081' # for SNB
	customer = 'DGH1'
	#res = _test_get_ps_graph_edge(_id, False)
	res = _test_get_ps_graph_edge(_id, True, customer)
	with open("threat_graph_api_test.json", "w") as wf:
		json.dump(res, wf, indent=4)

def _test_lrapi_():
	api = __get_lrapi__()
	device_id = "299aab0ea3724c58b7f86b0dedddc140"
	print api.send_containment_message(device_id)

def __main__():
	#_test_containment(False)
	#_test_lrapi_()
	_test_tgapi_()
	#_test_csapi_meta_()

if __name__ == '__main__':
	__main__()

