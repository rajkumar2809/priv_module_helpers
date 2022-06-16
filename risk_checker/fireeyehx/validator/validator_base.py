# -*- coding: utf-8 -*-

import os, sys
import json, re, glob
from logging import getLogger
from ipaddress import ip_address, IPv6Address

dirpath = os.path.dirname( os.path.abspath(__file__) )+"/"
apppath = dirpath+"../../"

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
			self.product = product.lower()
		else:
			self.product = alert["alert_src"]["product"].lower()
		if customer:
			self.customer = customer
		else:
			self.customer = alert["alert_src"]["customer_name"]
		self.version = alert["versions"]
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
			self.validate_conf = validator_config.get("validate_conf")
		#self.message = []
		self.results = {}
	
	def get_type(self):
		return self.alert_type

	def get_results(self):
		return self.is_positive, self.is_gray, self.results

	def validate_falsepositive(self):
		assert False, "you need to inherit"

	def _check_cyfirma_nw_dst(self, nw_access):
		def get_nwlist(nw_access):
			results = {}
			for each in nw_access:
				each = each["nw_dst"]
				dstip = each.get("ip")
				if dstip and len(dstip) > 6:
					if self._is_private_ip(dstip):
						continue
					results[dstip] = { "name" : each.get("name"), "ip" : dstip }
			return results.values()
		nwlist = get_nwlist(nw_access)
		results = self.cyfirma.check_domains([ each["name"] for each in nwlist
			if each.get("name") and len(each["name"])>0 ])
		if len(results) is 0:
			results = self.cyfirma.check_ipv4([ each["ip"] for each in nwlist
				if each.get("ip") and len(each["ip"])>0])
		detected = len(results) is not 0 or len(results) is not 0
		return detected, results

	def _check_cyfirma_hash(self, ev_details, main_event=None):
		def get_pslist(ev_details):
			results = {}
			for each in ev_details:
				each = each["process_info"]
				pshash = each["hash"]
				if pshash and not pshash in results:
					results[pshash] = { "name" : each["path"], "hash" : pshash }
				pshash = each["parent_hash"]
				if pshash and not pshash in results:
					results[pshash] = { "name" : each["parent_name"], "hash" : pshash }
			return results.values()
		pslist = get_pslist(ev_details)
		hashlist = [ each["hash"] for each in pslist ]
		if main_event:
			tgtapp = main_event.get("target_app")
			if tgtapp and "sha256Hash" in tgtapp:
				tgthash = tgtapp["sha256Hash"]
				if isinstance(tgthash, basestring) and not tgthash in hashlist:
					hashlist.append(tgthash)
					pslist.append( { "name" : tgtapp.get("applicationName"), "hash" : tgthash } )
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

