# -*- coding: utf-8 -*-

import sys, os
import time, json, re, copy
from datetime import datetime
import cb_api_conf as cfg_util
from monkey_tools.utils import time_util

from connectors.cbdefense_api.v6_api import cb_api
from connectors.cbdefense_api.v6_api import cb_api_parser as parser
from connectors.cbdefense_api.v6_api import cb_api_constant as const

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )

def get_customers():
	return cfg_util.get_customers()

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
	_key_=const.ApiKey.EventSimple.ParsedKey
	result = {
		_key_.PROCESS : event[_key_.PROCESS],
		_key_.PARENT : event[_key_.PARENT],
		_key_.USER : event[_key_.USER]
	}
	value = event[_key_.EV_TYPE]
	if isinstance(value, list):
		result[_key_.EV_TYPE] = value
	else:
		result[_key_.EV_TYPE] = [value] if len(value)>0 else []
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
	_key_=const.ApiKey.EventSimple.ParsedKey
	result = {}
	for each in events:
		each_ps = sammarize_each_process(each)
		key = each_ps[_key_.PROCESS][_key_.PPID]
		if result.has_key(key):
			eventlist  = list(set(
				result[key][_key_.EV_TYPE]+each_ps[_key_.EV_TYPE]))
			categories = list(set(
				result[key][_key_.CATEGORIES]+each_ps[_key_.CATEGORIES]))
			killchains = list(set(
				result[key][_key_.KILLCHAIN_STATE]+each_ps[_key_.KILLCHAIN_STATE]))
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

def _parse_app_detail(events, by_alert=True):
	_KEYTOP_= const.ApiKey

	def parse_for_process_info(process, parent):
		_key_ = _KEYTOP_.Events.ParsedKey
		parent_prefix = "parent_"
		result = {}
		process_path = process.get(_key_.NAME)
		parent_path  = parent.get(_key_.NAME)
		result[_key_.PPID]=process[_key_.PPID]
		result[_key_.PID]=process[_key_.PID]
		result[_key_.PATH]=process[_key_.PATH]
		result[_key_.HASH]=process[_key_.HASH]
		result[_key_.COMLINE]=process[_key_.COMLINE]
		result[_key_.Reputation]=process[_key_.Reputation]
		result[parent_prefix+_key_.PID]=parent[_key_.PID]
		result[parent_prefix+_key_.HASH]=parent[_key_.HASH]
		result[parent_prefix+_key_.NAME]=parent[_key_.NAME]
		result[parent_prefix+_key_.PATH]=parent.get(_key_.PATH)
		result[parent_prefix+_key_.COMLINE]=parent[_key_.COMLINE]
		result[parent_prefix+_key_.Reputation]=parent[_key_.Reputation]
		return result

	def parse_for_event_info(event):
		_key_ = _KEYTOP_.Alert.ThreatInfo.ParsedKey
		_key_ps_ = _KEYTOP_.Events.ParsedKey
		result = {}
		result[_key_.Events_ID]=[event[_key_.Events_ID]]
		result[_key_ps_.PPID]=event["process"][_key_ps_.PPID]
		result[_key_.Events_USER]=event[_key_.Events_USER]
		result[_key_.Events_TIME]=[event[_key_.Events_TIME]]
		result[_key_.Events_EV_TYPE]=event[_key_.Events_EV_TYPE]
		result[_key_.Events_RAW_EV_TYPE]=event[_key_.Events_RAW_EV_TYPE]
		result[_key_.Events_KILLCHAIN_STATE]=event[_key_.Events_KILLCHAIN_STATE]
		result[_key_.Events_CATEGORIES]=event[_key_.Events_CATEGORIES]
		result[_key_.Events_DESCRIPTION]=event[_key_.Events_DESCRIPTION]
		result[_key_.Events_EVENT_SUMMARY]=event[_key_.Events_EVENT_SUMMARY]
		result[_key_.Events_EVENT_DETAIL]=event[_key_.Events_EVENT_DETAIL]
		result[_key_.Events_EVENTNUM]=1
		return result

	def parse_for_indicator_info(current, indicators):
		return list(set(current+indicators))

	def shrink_event_info(all_events):
		_key_ = _KEYTOP_.Events.ParsedKey
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
		_key_ = _KEYTOP_.Events.ParsedKey
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
	def __init__(self, host, port, connector_id, api_key, org_key, **others):
		self.api = cb_api.CbApi(host, port, connector_id, api_key, org_key)
		self.host = host
		self.port = port
		self.connector_id = connector_id
		self.api_key = api_key
		self.org_key = org_key

	def get_malware_app_detail(self, event_id, with_app_type=False):
		assert isinstance(event_id, basestring), "only accept 1 event_id with str"
		_ev = self._get_event_detail_obj(event_id)
		return _ev.get_malware_app(with_app_type)

	def get_malware_applist(self, event_id):
		assert isinstance(event_id, basestring), "only accept 1 event_id with str"
		_ev = self._get_event_detail_obj(event_id)
		return _ev.get_malware_applist(with_app_type)

	def get_event_detail(self, event_id, only_first=True):
		evlist = self._get_event_detail_obj(event_id)
		if only_first:
			_ev = evlist[0]
			return _ev.to_dict()
		else:
			results = []
			for each in evlist:
				results.append(each.to_dict())
			return results

	def get_alert_detail(self, alert_id):
		_raw = self.api.get_alert_detail(alert_id)
		_alert = parser.CbApiMapToAlert(_raw)
		return _alert.to_dict()

	def search(self, query, search_window="-2w", rows=1000, is_detail=False):
		assert isinstance(query, basestring), "quey is accept only string"
		assert isinstance(search_window, basestring), "search_window is accept only string"
		if not search_window.startswith("-"):
			search_window = "-"+search_window
		res = self.api.search(query, search_window=search_window, rows=rows)
		if is_detail:
			idlist = [ each[const.ApiKey.EventSimple.ID]
						for each in res["results"] ]
			events = []
			for i in range(0, (len(idlist)/100)+1):
				index= i*100
				_ids = idlist[index:index+100] 
				if _ids:
					each = self._get_event_detail_obj(_ids)
					events.extend(each)
		else:
			events = [ parser.CbApiMapToEvent(ev) for ev in res["results"] ]
		results = [ each.to_dict() for each in events ]
		return results

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

	def reputation_sha256(self, value, op="search",
			list_type="BLACK_LIST", filename="unknown"):
		op = op.lower()
		assert op in ("add", "delete", "search"), "op accept only add,delete,search"
		today = time_util.get_date(time_util.YMDHMS)
		if op == "add":
			list_type = list_type.upper()
			assert list_type in ("WHITE_LIST", "BLACK_LIST"), "list type accept only WHITE_LIST or BLACK_LIST"
			data={
				"description": "MDR Service {}".format(today),
				"override_list": list_type,
				"override_type": "SHA256",
				"sha256_hash": value,
				"filename": filename
			}
			return self.api.reputation_add(data)
		else:
			data = { "query" : value }
			res = self.api.reputation_search(data)
		if op == "delete":
			if res.get("results"):
				_id = res["results"][0]["id"]
				return self.api.reputation_delete(_id)
			else:
				return False
		else:
			return res

	def start_live_response(self, device_id):
		api = cb_api.CbApiLiveResponse(
				self.host,
				self.port,
				self.connector_id,
				self.api_key,
				self.org_key)
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

	# private

	def _quarantine(self, device_id, enable=True):
		if isinstance(device_id, int):
			device_id = str(device_id)
		api = cb_api.CbApi(
				self.host,
				self.port,
				self.connector_id,
				self.api_key,
				self.org_key)
		return api.quarantine(device_id, enable)

	def _get_event_detail_obj(self, event_id):
		for i in range(1, 3):
			try:
				_raw = self.api.get_event_detail(event_id)
				results = []
				for each in _raw:
					_ev = parser.CbApiMapToEventDetail(each)
					results.append(_ev)
				return results
			except Exception as e:
				pass
		raise e

def init_by_cfg_file(customer_info, api_type="rest"):
	conf = cfg_util.get_conf(customer_info)
	api_type = api_type.lower()
	if api_type == "lr":
		token = conf["tokens"]["lr"]
	elif api_type == "ex":
		token = conf["tokens"]["ex"]
	else:
		token = conf["tokens"]["rest"]
	if not conf["host"].startswith("defense-"):
		conf["host"] = "defense-"+conf["host"]
	_key, connector_id = token.split("/")
	org_key = conf["org_key"]
	return CbApiHelper(
		conf["host"], int(conf["port"]), connector_id, _key, org_key)

def __test__alert():
	api = init_by_cfg_file("dhsoc", "rest")
	alert = api.get_alert_detail('38846EED')
	for each in alert["events"]:
		print each["network"]

def __test__device():
	api = init_by_cfg_file("dhsoc", "rest")
	device_name = "desktop-llvam1d"
	res = api.get_device_list(host_name=device_name)
	print json.dumps(res, indent=4)

def __get_event_detail():
	api = init_by_cfg_file("dhsoc", "rest")
	idlist = [ "c912b42ad3f011eba2c88fa881a3e217" ]
	res = api.get_event_detail(idlist)
	print res

def __test__events():
	api = init_by_cfg_file("dhsoc", "rest")
	device_name = "desktop-llvam1d"
	res = api.get_events(hostname=device_name)
	print json.dumps(res, indent=4)

def __test__processes():
	api = init_by_cfg_file("dhsoc", "rest")
	device_name = "desktop-llvam1d"
	res = api.get_processes(hostname=device_name)
	print json.dumps(res, indent=4)

def __test_customers():
	print get_customers()

def __test_sammarize_event_detail():
	with open("sample/events.json") as f:
		events = json.load(f)
	results = [ sammarize_event_detail(ev) for ev in events ]
	print len(results)

def __test_sammarize_each_process():
	with open("sample/raw-event-simple.json") as f:
		raw = json.load(f)
	events = []
	for each in raw["results"]:
		events.append(parser.CbApiMapToEvent(each))
	results = sammarize_each_process(events[0])
	print results

def __test_sammarize_events_process_list():
	with open("sample/raw-event-simple.json") as f:
		raw = json.load(f)
	events = []
	for each in raw["results"]:
		events.append(parser.CbApiMapToEvent(each))
	results = sammarize_events_process_list(events)
	print len(results)

def __test_sammarize_events():
	with open("sample/raw-event-simple.json") as f:
		raw = json.load(f)
	events = []
	for each in raw["results"]:
		events.append(parser.CbApiMapToEvent(each))
	results = sammarize_events(events)
	print len(results)

def __test_sammarize_each_event():
	with open("sample/raw-event-simple.json") as f:
		raw = json.load(f)
	events = []
	for each in raw["results"]:
		events.append(parser.CbApiMapToEvent(each))
	results = sammarize_each_event(events[0])
	print results

def __test_parse_alert():
	with open("sample/alert.json") as f:
		raw = json.load(f)
	alert = _parse_alert(raw)
	with open("after-alert.json", "w") as wf:
		json.dump(alert, wf, indent=4)

def __test_get_malware_related_events():
	with open("sample/raw-events-detail.json") as f:
		raw = json.load(f)
	events = []
	for each in raw:
		events.append(parser.CbApiMapToEventDetail(each))
	results = _get_malware_related_events(events)
	print len(results)

def __test_get_sammarize_alert():
	with open("sample/alert.json") as f:
		raw = json.load(f)
	alert = _parse_alert(raw)
	results = sammarize_alert(alert)
	print json.dumps(results, indent=4)

def __test__parse_app_detail():
	with open("sample/alert.json") as f:
		raw = json.load(f)
	#alert = parser.CbApiMapToAlert(raw)
	alert = _parse_alert(raw)
	results = _parse_app_detail(alert["events"])
	with open("threat_app_detail.json", "w") as wf:
		json.dump(results, wf, indent=4)

def __test_lr_send_command():
	api = init_by_cfg_file("dhsoc", "lr")
	test_device = 28320239
	com = "msg.exe */server:localhost /TIME:0 \"テストメッセージ\" "
	res = api.lr_send_command(test_device, com)
	print res

def __test_quarantine():
	api = init_by_cfg_file("dhsoc", "ex")
	test_device = 28320239
	print api.quarantine(test_device)

def __test_unquarantine():
	api = init_by_cfg_file("dhsoc", "ex")
	test_device = 28320239
	print api.unquarantine(test_device)

def __test_search():
	api = init_by_cfg_file("dhsoc", "rest")
	#q = "device_name:desktop-llvam1d AND process_name:explorer.exe"
	q = "device_name:desktop-llvam1d"
	res = api.search(q, is_detail=True)
	print len(res)

if __name__ == '__main__':
	__test__alert()

