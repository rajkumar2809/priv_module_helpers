# -*- coding: utf-8 -*-

import sys, os
import time, json, re, copy
from datetime import datetime
import cb_api_conf as cfg
from monkey_tools.utils import time_util
from connectors.cbdefense_api import cb_api
from connectors.cbdefense_api import cb_api_parser as parser
from connectors.cbdefense_api import cb_api_constant as const

"""
connector_id for DHSOC:xxxxx

(example) 1. get start
api = CbApi("dhsoc")
result = api.get_alert_detail('FXIQYAQG')

(example) 2. get alert detail
alert = parser.CbApiMapToAlert(result)
# FX1QYAQG is alert_id. dhsoc is customer id

(example) 3. get network access info from alert detail
api = CbApi("dhsoc")
result = api.get_alert_detail('FXIQYAQG')
alert = parser.CbApiMapToAlert(result)
for each in alert.to_dict()["events"]:
	print each["network"]
"""

def get_customers():
	return cfg.get_customers()

def sammarize_event_detail(event):
	result = {} 
	for k,v in event.items():
		msg = []
		if isinstance(v, dict):
			for ik, iv in v.items():
				msg.append( "{}:< {} >".format(ik, str(iv)) )
		elif isinstance(v, list) or isinstance(v, tuple):
			for each in v:
				msg.append( str(v) )
		else:
			msg.append( str(v) )
		result[k] = msg
	return result

def sammarize_each_event(event):
	if isinstance(event, parser.CbApiMapToEvent):
		event = event.to_dict() 
	_key_=const.ApiKey.Events.ParsedKey
	result = {
		_key_.ID : event[_key_.ID],
		_key_.PPID : event[_key_.PROCESS][_key_.PPID],
		_key_.PID : event[_key_.PROCESS][_key_.PID],
		_key_.TIME : event[_key_.TIME],
		_key_.EV_TYPE : event[_key_.EV_TYPE],
		_key_.KILLCHAIN_STATE : event[_key_.KILLCHAIN_STATE],
		_key_.CATEGORIES : event[_key_.CATEGORIES],
		_key_.DESCRIPTION : "",
		_key_.SHORT_DESCRIPTION : event[_key_.DESCRIPTION] }
	return result

def sammarize_events(events):
	assert isinstance(events, list), "only acceptable list object at argments"
	_key_=const.ApiKey.Events.ParsedKey
	result = []
	tmp = {}
	for each in events:
		each_info = sammarize_each_event(each)
		_time = each_info[_key_.TIME]
		if not tmp.has_key(_time):
			tmp[_time] = []
		tmp[_time].append(each_info)
	for otime, info_list in sorted(tmp.items()):
		normal=[]
		action=[]
		for each in info_list:
			if each[_key_.EV_TYPE].startswith("POLICY"):
				action.append(each)
			else:
				normal.append(each)
		result += normal+action
	return result

def sammarize_each_process(event):
	if isinstance(event, parser.CbApiMapToEvent):
		event = event.to_dict()
	_key_=const.ApiKey.Events.ParsedKey
	result = {
		_key_.PROCESS : event[_key_.PROCESS],
		_key_.PARENT : event[_key_.PARENT],
		_key_.USER : event[_key_.USER]
	}
	value = event[_key_.EV_TYPE]
	result[_key_.EV_TYPE] = value if len(value)>0 else []
	value = event[_key_.CATEGORIES]
	if isinstance(value, list):
		result[_key_.CATEGORIES] = value
	else:
		result[_key_.CATEGORIES] = [value] if len(value)>0 else []
	value = event[_key_.KILLCHAIN_STATE]
	if isinstance(value, list):
		result[_key_.KILLCHAIN_STATE] = value
	else:
		result[_key_.KILLCHAIN_STATE] = [value] if len(value)>0 else []
	return result

def sammarize_events_process_list(events):
	assert isinstance(events, list), "only acceptable list object at argments"
	_key_=const.ApiKey.Events.ParsedKey
	result = {}
	for each in events:
		each_ps = sammarize_each_process(each)
		key = each_ps[_key_.PROCESS][_key_.PPID]
		if result.has_key(key):
			eventlist = list(set(result[key][_key_.EV_TYPE]+each_ps[_key_.EV_TYPE]))
			categories = list(set(result[key][_key_.CATEGORIES]+each_ps[_key_.CATEGORIES]))
			killchains = list(set(result[key][_key_.KILLCHAIN_STATE]+each_ps[_key_.KILLCHAIN_STATE]))
			result[key][_key_.EV_TYPE] = eventlist
			result[key][_key_.CATEGORIES] = categories
			result[key][_key_.KILLCHAIN_STATE] = killchains
		else:
			result[key] = each_ps
	return result

def sammarize_alert(origin):
	alert = copy.deepcopy(origin)
	alert["event_num"] = len(alert["events"])
	del(alert["events"])
	return alert

def _get_malware_related_events(events):
	def has_malware_indicator(event):
		pt = r"(?i)(detect|pup|suspect|suspicious)(ed)?_.*_(drop|app)"
		for each_indicator in event.categories:
			if "NON_MALWARE" in each_indicator:
				continue
			elif "MALWARE" in each_indicator:
				return True
			elif re.search(pt, each_indicator):
				return True
		return False

	relate_events = []
	for each in events:
		if has_malware_indicator(each):
			relate_events.append(each)
	return relate_events

def _parse_alert(api_alert_detail_json):
	alert = parser.CbApiMapToAlert(api_alert_detail_json)
	return alert.to_dict()

def _parse_app_detail(events):
	_key_= const.ApiKey.Events.ParsedKey

	def parse_for_process_info(process, parent):
		parent_prefix = "parent_"
		result = {}
		result[_key_.PPID]=process[_key_.PPID]
		result[_key_.PID]=process[_key_.PID]
		result[_key_.PATH]=process[_key_.PATH]
		result[_key_.HASH]=process[_key_.HASH]
		result[_key_.COMLINE]=process[_key_.COMLINE]
		result[parent_prefix+_key_.PID]=parent[_key_.PID]
		result[parent_prefix+_key_.HASH]=parent[_key_.HASH]
		result[parent_prefix+_key_.NAME]=parent[_key_.NAME]
		result[parent_prefix+_key_.COMLINE]=parent[_key_.COMLINE]
		return result

	def parse_for_event_info(event):
		result = {}
		result[_key_.ID]=[event[_key_.ID]]
		result[_key_.PPID]=event["process"][_key_.PPID]
		result[_key_.USER]=event[_key_.USER]
		result[_key_.TIME]=[event["occurred"]]
		result[_key_.EV_TYPE]=event["ev_type"]
		result[_key_.KILLCHAIN_STATE]=event["attack_phase"]
		result[_key_.CATEGORIES]=event["categories"]
		result[_key_.DESCRIPTION]=event["description"]
		result[_key_.EVENTNUM]=1
		return result

	def parse_for_indicator_info(current, indicators):
		return list(set(current+indicators))

	def shrink_event_info(all_events):
		result = all_events
		for ppid, each_all in all_events.items():
			tmp={}
			events = []
			for each_ev in each_all["events"]:
				ev_type = each_ev[_key_.EV_TYPE]
				if ev_type in tmp:
					exist_flag = False
					each_desc = each_ev[_key_.DESCRIPTION]
					for known_event in tmp[ev_type]:
						if known_event[_key_.DESCRIPTION] == each_desc:
							exist_flag = True
							known_event[_key_.EVENTNUM] += 1
							known_event[_key_.TIME].extend(each_ev[_key_.TIME])
							known_event[_key_.ID].extend(each_ev[_key_.ID])
					if not exist_flag:
						tmp[ev_type].append( each_ev )
				else:
					tmp[ev_type] = [ each_ev ]
			for each in tmp.values():
				events += each
			result[ppid]["events"] = events
		return result.values()

	tmp= {}
	for each in events:
		ppid = each["process"][_key_.PPID]
		event = parse_for_event_info(each)
		if not tmp.has_key(ppid):
			tmp[ppid] = {"events" :[], "indicators":[]}
			tmp[ppid]["process_info"] = parse_for_process_info(
					each["process"], each["parent_process"])
		tmp[ppid]["events"].append( event )
		tmp[ppid]["indicators"] = parse_for_indicator_info(
				tmp[ppid]["indicators"], each["categories"] )
	result = shrink_event_info(tmp)
	return result

class CbApiHelper(object):
	def __init__(self, host, port, connector_id, api_key, org_key=None, **others):
		self.api = cb_api.CbApi(host, port, connector_id, api_key)
		self.host = host
		self.port = port
		self.connector_id = connector_id
		self.api_key = api_key
		self.org_key = org_key

	def get_malware_app_detail(self, event_id, with_app_type=False):
		_ev = self._get_event_detail_obj(event_id)
		return _ev.get_malware_app(with_app_type)

	def get_event_detail(self, event_id):
		_ev = self._get_event_detail_obj(event_id)
		return _ev.to_dict()

	def _get_event_detail_obj(self, event_id):
		_raw = self.api.get_event_detail(event_id)
		_ev = parser.CbApiMapToEventDetail(_raw)
		return _ev

	def get_alert_detail(self, alert_id):
		_raw = self.api.get_alert_detail(alert_id)
		_alert = parser.CbApiMapToAlert(_raw)
		return _alert.to_dict()

	def get_device_list(self, filter_days=30, ip_addr=None, host_name=None):
		queries = {}
		if ip_addr:
			queries["ip_addr"] = ip_addr
		if host_name:
			queries["hostname"] = host_name
		return self.api.get_device_list(filter_days, **queries)

	def get_processes(self, rows=100,
			hostname  = None,
			user_name = None, is_exact_user = False,
			ip_addr   = None, search_window = None ):
		# useful options (hostname,hostname_exact,owner,owner_exact,ip_addr,search_window)
		op = {}
		op["ip_addr"]=ip_addr
		op["search_window"]=search_window
		op["hostname_exact"]=hostname
		if is_exact_user:
			op["owner_exact"] = user_name
		else:
			op["owner"] = user_name
		_raw = self.api.get_processes(rows = rows, **op)
		return parser.parse_process_list(_raw)

	def get_events(self, rows=100,
			hostname  = None, is_exact_host = False,
			user_name = None, is_exact_user = False,
			ip_addr   = None,
			app_name  = None,
			hash_sha256   = None,
			event_type    = None,
			search_window = None ):
		op = {}
		op["app_name"]    = app_name
		op["hash_sha256"] = hash_sha256
		op["ip_addr"]     = ip_addr
		op["event_type"]  = event_type
		op["search_window"] = search_window
		if is_exact_host:
			op["hostname_exact"] = hostname
		else:
			op["hostname"] = hostname
		if is_exact_user:
			op["owner_exact"] = user_name
		else:
			op["owner"] = user_name
		_raw = self.api.get_events(rows=rows, **op)
		return parser.parse_event_list(_raw)

	def start_live_response(self, device_id):
		api = cb_api.CbApiLiveResponse(
				self.host,
				self.port,
				self.connector_id,
				self.api_key)
		api.connect_to(device_id)
		return api

	def lr_send_command(self, device_id, commands):
		session = self.start_live_response(device_id)
		if isinstance(commands, list):
			is_success = False
			for eachcom in commands:
				each_success, result = session.create_process(eachcom)
				if each_success:
					is_success = each_success
		else:
			is_success, result = session.create_process(commands)
		return is_success

	def quarantine(self, device_id):
		return self._quarantine(device_id, True)

	def unquarantine(self, device_id):
		return self._quarantine(device_id, False)

	def _quarantine(self, device_id, enable=True):
		api = cb_api.CbApiEx(
				self.host,
				self.port,
				self.connector_id,
				self.api_key,
				self.org_key)
		return api.quarantine(device_id, enable)

def init_by_cfg_file(customer_info, api_type="rest"):
	conf = cfg.get_conf(customer_info)
	api_type = api_type.lower()
	if api_type == "lr":
		token = conf["tokens"]["lr"]
		conf["host"] = "api-"+conf["host"]
	elif api_type == "ex":
		token = conf["tokens"]["ex"]
		if conf.get("exhost"):
			conf["host"] = conf["exhost"]
		else:
			conf["host"] = "defense-"+conf["host"]
	else:
		token = conf["tokens"]["rest"]
		conf["host"] = "api-"+conf["host"]
	_key, connector_id = token.split("/")
	if "org_key" in conf:
		org_key = conf["org_key"]
		return CbApiHelper(
			conf["host"], int(conf["port"]), connector_id, _key, org_key)
	else:
		return CbApiHelper(
			conf["host"], int(conf["port"]), connector_id, _key)

def __test__rest():
	api = init_by_cfg_file("dhsoc", "rest")
	alert = api.get_alert_detail('NKYXE2OS')
	for each in alert["events"]:
		print each["network"]

def __test__ex():
	api = init_by_cfg_file("DGH1", "ex")
	device_id = "10917092"
	print api.quarantine(device_id)

if __name__ == '__main__':
	__test__ex()
