# -*- coding: utf-8 -*-

import os, sys
import json, re, glob
from logging import getLogger
from ipaddress import ip_address, IPv6Address

#from . import BLACK, WHITE, GRAY, TYPECODE_HIDDEN, TYPECODE_GENERAL, TYPECODE_MALWARE, TYPECODE_RANSOM, TYPECODE_NOISE

dirpath = os.path.dirname( os.path.abspath(__file__) )+"/"
apppath = dirpath+"../../"

_IMPORTANT_THREAT_TAGs = [
	"FAKE_APP",
	"REVERSE_SHELL",
	"KNOWN_BACKDOOR",
	"KNOWN_DOWNLOADER",
	"LATERAL_MOVEMENT"
]

class ValidatorBase(object):
	@classmethod
	def is_target(cls, alert):
		assert False, "you can instanciate only subclass ValidatorBase"

	def __init__(self, alert, typecode, logger,
			product=None, customer=None, cyfirma=None, validator_config=None,
			intel=None, vtapi=None, rm_helper=None):
		self.logger = logger
		self.alert = alert
		self.alert_type = typecode
		if product:
			self.product = product
		else:
			self.product = alert["alert_src"]["product"]
		if customer:
			self.customer = customer
		else:
			self.customer = alert["alert_src"]["sensor_id"]
		if "versions" in alert:
			self.version = alert["versions"]
		else:
			self.version = None
		self.is_positive = True
		self.is_gray  = False
		self.is_emerg = False
		self.correct_severity = None
		self.cyfirma = cyfirma
		self.intel = intel
		self.vtapi = vtapi
		self.rm_helper = rm_helper
		if validator_config:
			self.app_map = validator_config.get("app_map")
			self.add_conf = validator_config.get("add_conf")
		self.message = []
		self.results = {}
	
	def get_type_by_str(self):
		return "behavior"

	def get_type(self):
		return self.alert_type

	def get_results(self):
		return self.is_positive, self.is_gray, self.results

	def validate_falsepositive(self):
		assert False, "you need to inherit"

	def _check_cyfirma_nw_dst(self, nw_access=None):
		#def get_nwlist(nw_access):
		#	results = {}
		#	for each in nw_access:
		#		each = each["nw_dst"]
		#		dstip = each.get("ip")
		#		if dstip and len(dstip) > 6:
		#			if self._is_private_ip(dstip):
		#				continue
		#			results[dstip] = { "name" : each.get("name"), "ip" : dstip }
		#	return results.values()
		##nwlist = get_nwlist(nw_access)
		nwlist = self._get_global_access()
		if nwlist:
			results = self.cyfirma.check_domains([ each["name"] for each in nwlist
				if each.get("name") and len(each["name"])>0 ])
			if len(results) is 0:
				results = self.cyfirma.check_ipv4([ each["ip"] for each in nwlist
					if each.get("ip") and len(each["ip"])>0 ])
			detected = len(results) is not 0 or len(results) is not 0
			return detected, results
		else:
			return False, []

	def _get_process_hash_list(self):
		ev_details = self._get_event_detail(self.alert)
		main_event = self.alert["alert_detail"]["threat_cause_event_detail"]
		def get_psdict(ev_details):
			results = {}
			for each in ev_details:
				psinfo = each["process_info"]
				pshash = psinfo["hash"]
				if pshash and not pshash in results:
					results[pshash] = { "name" : psinfo["path"], "hash" : pshash }
				pshash = psinfo["parent_hash"]
				if pshash and not pshash in results:
					results[pshash] = { "name" : psinfo["parent_name"], "hash" : pshash }
			return results
		psdict = get_psdict(ev_details)
		if main_event:
			tgtapp = main_event.get("target_app")
			if tgtapp and "sha256Hash" in tgtapp:
				tgthash = tgtapp["sha256Hash"]
				if isinstance(tgthash, basestring) and not tgthash in psdict:
					psdict[tgthash] = { "name" : tgtapp.get("applicationName"),
										"hash" : tgthash }
		return psdict.values()

	def _check_cyfirma_hash(self, ev_details=None, main_event=None):
		#def get_pslist(ev_details):
		#	results = {}
		#	for each in ev_details:
		#		each = each["process_info"]
		#		pshash = each["hash"]
		#		if pshash and not pshash in results:
		#			results[pshash] = { "name" : each["path"], "hash" : pshash }
		#		pshash = each["parent_hash"]
		#		if pshash and not pshash in results:
		#			results[pshash] = { "name" : each["parent_name"], "hash" : pshash }
		#	return results.values()
		#pslist = get_pslist(ev_details)
		#hashlist = [ each["hash"] for each in pslist ]
		#if main_event:
		#	tgtapp = main_event.get("target_app")
		#	if tgtapp and "sha256Hash" in tgtapp:
		#		tgthash = tgtapp["sha256Hash"]
		#		if isinstance(tgthash, basestring) and not tgthash in hashlist:
		#			hashlist.append(tgthash)
		#			pslist.append( { "name" : tgtapp.get("applicationName"), "hash" : tgthash } )
		pslist = self._get_process_hash_list()
		hashlist = [ each["hash"] for each in pslist ]
		results = self.cyfirma.check_hashes(hashlist)
		if len(results) is 0:
			return False, []
		else:
			mals = {}
			for each in results:
				malhashes = each["searchvalue"]
				if isinstance(malhashes, basestring):
					malhashes = [ malhashes ]
				for each_ps in pslist:
					if each_ps["hash"] in malhashes:
						mals[each_ps["hash"]] = each_ps
			return True, mals.values()

	def _get_event_detail(self, alert):
		if "versions" in alert:
			if alert["versions"] == "1.0":
				self.logger.debug("data version is v1.0")
				alert_detail = alert["alert_detail"]
			else:
				assert False, "unknown version"
		else:
			self.logger.debug("no information of data version")
			alert_detail = alert["alerts"][0]
		return alert_detail["threat_app_detail"]

	def _get_nw_access(self, alert):
		if "versions" in alert:
			if alert["versions"] == "1.0":
				alert_detail = alert["alert_detail"]
			else:
				assert False, "unknown version"
		else:
			alert_detail = alert["alerts"][0]
		return alert_detail["network_access"]

	def _get_app_name(self, app_path):
		ext_map  = self.app_map["extension"]
		path_map = self.app_map["file_path"]
		if "." in app_path:
			ext = app_path.rsplit(".", 1)[-1].lower()
			if ext_map.has_key(ext):
				return self.app_map["extension"][ext]
		for each in path_map:
			regex = each.get("regex")
			name  = each.get("name")
			exrule = each.get("exclude")
			try:
				if regex and name and re.search(regex, app_path):
					self.logger.debug("{} match with {}".format(app_path, regex))
					if exrule:
						for each_exc in exrule:
							if re.search(each_exc, app_path):
								self.logger.debug("app_path match with exclude condition:{}".format(each_exc))
								continue
					return name
			except Exception as e:
				self.logger.warning(e.message)
				self.logger.warning("error occurred path_map {}/{}/{}".format(
					regex, name, str(exrule) ))
		if "\\" in app_path:
			return app_path.rsplit('\\')[-1]
		else:
			return app_path.rsplit('/')[-1]

	def _search_mydb(self, info, rec_type=None):
		for i in range(0, 3):
			try:
				return self.intel.search(info, self.product, self.customer, rec_type, max_count=1000)
			except OSError as e:
				self.logger.warning("error occurred at search_mydb({})".format(e.message))
			except IOError as e:
				self.logger.warning("error occurred at search_mydb({})".format(e.message))
		return []

	def _is_private_ip(self, dstip):
		customer_name = self.alert["alert_src"]["customer_name"]
		privates = self.add_conf["private_ipaddr"]
		if re.search(r"^10\.", dstip):
			return True
		elif re.search(r"^172\.0?(1[6-9]|2\d|3[01])\.", dstip):
			return True
		elif re.search(r"^192\.168\.", dstip):
			return True
		elif customer_name in privates:
			for each in privates[customer_name]:
				if re.search(each, dstip):
					return True
			return False
		else:
			return False

	def _get_global_access(self, nw_access=None):
		if nw_access is None:
			nw_access = self._get_nw_access(self.alert)
		results = {}
		for each in nw_access:
			each = each["nw_dst"]
			dstip = each.get("ip")
			if dstip and len(dstip) > 6:
				if self._is_private_ip(dstip):
					continue
				#results[dstip] = { "name" : each.get("name"), "ip" : dstip }
				results[dstip] = each
		return results.values()

	def _has_listen_port(self, nw_access=None):
		if nw_access is None:
			nw_access = self._get_nw_access(self.alert)
		results = {}
		for each in nw_access:
			nw_dst    = each["nw_dst"]
			dstip     = each.get("ip")
			proto     = each["protocol"]
			direction = each.get("nw_direction")
			if direction == "IN":
				results[dstip] = each
				return True
		return False

	def _get_important_tags(self, tags=None):
		if tags is None:
			tags = self.alert["alert_summary"]["threat_tags"]
			if not tags:
				return []
		return [ { "tag" : each } for each in _IMPORTANT_THREAT_TAGs
					if each in tags ]
	
	def _get_shell_type(self, app_name):
		if app_name in self.app_map["script_type"]:
			return 1
		elif app_name in self.app_map["powerfull_shell"]:
			return 5
		else:
			return 0

	def _is_main_process(self, ppid):
		main_event = self.alert["alert_detail"]["threat_cause_event_detail"]
		if main_event:
			pid   = main_event["process"].get("processId")
			phash = main_event["select_app"].get("sha256Hash")
			if phash and pid:
				main_ppid = "{}-{}-0".format(pid, phash)
				return main_ppid == ppid
		return False

