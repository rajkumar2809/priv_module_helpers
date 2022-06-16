# -*- coding: utf-8 -*-

import os, sys
import json, re, glob, logging
from ipaddress import ip_address, IPv6Address

dirpath = os.path.dirname( os.path.abspath(__file__) )+"/"
apppath = dirpath+"../../"

BLACK = 0xf
WHITE = 0x0
GRAY  = 0x8
WGRAY = 0x1
BGRAY = 0xe

logger =logging.getLogger()

class GeneralValidator(object):
	@classmethod
	def is_target(cls, alert):
		return True # general type is possible to target all alerts

	def __init__(self, alert, product, intel, vtapi=None, app_map=None, cyfirma=None):
		self.alert = alert
		self.version = alert["versions"]
		self.customer = alert["alert_src"]["customer_name"]
		self.product = product
		self.is_positive = True
		self.is_gray = False
		self.intel = intel
		self.vtapi = vtapi
		self.cyfirma = cyfirma
		self.app_map = app_map
		self.results = []
	
	def _get_application_name(self, ev):
		if "event_desc" in self.app_map:
			for each in self.app_map["event_desc"]:
				ps_name, pt = each["ps_name"], each["pattern"]
				msg = ev["description"]
				if re.search(pt, msg):
					return ps_name
		if "application_name" in self.app_map:
			for each in self.app_map["application_name"]:
				ps_name, field, value = each["ps_name"], each["field"], each["value"]
				if self.alert["alert_detail"].get("process_detail"):
					for each in self.alert["alert_detail"]["process_detail"]:
						if ev["ps_name"] == each["ps_name"]:
							target = each.get(field)
							if target and re.search(value, target):
								return ps_name
		return ev["ps_name"]

	def validate_falsepositive(self):
		if self._is_noise():
			return self._check_fp_for_noise()
		for ev in self.alert["alert_detail"]["event_detail"]:
			ps_pid = ev["ps_pid"]
			if isinstance(self.app_map, dict):
				ps_name = self._get_application_name(ev)
			else:
				ps_name = ev["ps_name"]
			if not isinstance(ps_name, basestring):
				ps_name = str(ps_name)
			search_key = ps_name.lower()
			records = self.search_mydb( search_key, "condition" )
			is_match = False
			for rec in records:
				rec_id = rec.get("id")
				rec_rev = rec.get("rev")
				reputation = rec.get("reputation")
				message    = rec.get("message")
				detail = rec.get("detail")
				try:
					is_match = self.fp_check_event_by_each_record(ev, ps_name, ps_pid, rec,
						rec_id, rec_rev, reputation, message, detail)
					if is_match:
						logger.info("alert is matched ID:[{}] Rev:[{}]".format(
							rec.get("id"), rec.get("rev")))
						break
				except Exception as e:
					logger.error("unknown error at checking record ID:{}".format(rec_id))
			if is_match:
				if reputation == "white":
					flag = WHITE
				elif reputation == "gray":
					flag = GRAY
				else:
					flag = BLACK
			else:
				flag = BLACK
				message = "unmatched any conditions"
			key = "{}({})".format(ps_name, ps_pid)
			self.results.append( { key : [ flag, message ] } )
		is_positive = False
		for each in self.results:
			for v in each.values():
				if v[0] == BLACK:
					is_positive = True
					self.is_gray = False
					break
				elif v[0] == GRAY:
					is_positive = True
					self.is_gray = True
		self.is_positive = is_positive
		if self.is_positive:
			alert_type = self.alert["alert_summary"].get("alert_type")
			if  alert_type == "multi_extension":
				res = { alert_type : [ GRAY, "unknown multi extension detected" ] }
				self.results = [ res ]
				self.is_gray = True
				severity = "未"
			elif  alert_type == "tamper_falcon":
				res = { alert_type : [ GRAY, "tampering falcon sensor module." ] }
				self.results = [ res ]
				self.is_gray = True
				severity = "未"
			elif self.is_gray:
				severity = "未"
			else:
				severity = None
		else:
			severity = "-"
		allresults = self.get_message()
		return severity, allresults

	def fp_check_event_by_each_record(self, ev, ps_name, ps_pid,
				rec, rec_id, rec_rev, reputation, message, detail):
		is_match = None
		if not( isinstance(rec_id,  basestring) and
				isinstance(rec_rev, basestring) ):
			logger.warning(
					"this record is corrupt. ID:{}".format(rec_id))
			return None
		elif not reputation in ("black", "white", "gray"):
			logger.warning(
					"has no correct reputation info [{}]".format(rec))
			return None
		elif not(isinstance(detail, dict) and detail.get("expected")):
			logger.warning("record is corrupted. [{}]".format(rec))
			return None
		allconditions = detail["expected"]
		if not(isinstance(allconditions, list)):
			logger.warning("record is corrupted. [{}]".format(rec))
			return None
		is_match = True
		for cnd_group in allconditions:
			target, conditions = self._get_match_target(
					cnd_group, ps_name, ps_pid)
			if not(target and conditions):
				logger.info(
						"data or conditions are null(or blank).")
				is_match = False
			elif not self._is_match_allcondition(target, conditions):
				logger.debug(
						"unmatch condition.")
				is_match = False
		return is_match

	def get_message(self):
		message = []
		pos_flags = (GRAY, BLACK)
		for each in self.results:
			for k, v in each.items():
				if self.is_positive and v[0] in pos_flags:
					message.append({"ppid": k , "message" : v[1]})
				elif not self.is_positive and v[0] == WHITE:
					message.append({"ppid": k , "message" : v[1]})
		if len(message) is 0:
			return [ "cannot classified by positive or negative." ]
		else:
			return message

	# private

	def search_mydb(self, info, rec_type=None):
		"""
		@param info<dict> log dict.
		@param rec_type<str> record type(hash,network,condition etc). and default is None.
		@return <list<dict>> search result. dict is maked by _raw(json).
		"""
		for i in range(0, 3):
			try:
				return self.intel.search(info, self.product, self.customer, rec_type, max_count=1000)
			except OSError as e:
				logger.warning("error occurred at search_mydb({})".format(e.message))
			except IOError as e:
				logger.warning("error occurred at search_mydb({})".format(e.message))
		return []

	def _get_match_target(self, cnd_group, ps_name, ps_pid):
		if isinstance(cnd_group, dict):
			position = cnd_group.get("data_position")
			conditions = cnd_group.get("conditions")
			if isinstance(position, basestring):
				if position == "event_detail":
					logger.debug("data position is event_detail")
					data = self.alert["alert_detail"]["event_detail"]
					data = [] if data is None else data
					for each in data:
						if ps_pid == each.get("ps_pid"):
							return each, conditions
				elif position == "process_detail":
					logger.debug("data position is process_detail")
					data = self.alert["alert_detail"]["process_detail"]
					data = [] if data is None else data
					for each in data:
						if ps_pid == each.get("ps_pid"):
							return each, conditions
		return None, None

	def _is_match_allcondition(self, target, conditions):
		def is_match(data, cond):
			field = cond["field"]
			value = cond["value"]
			dtype = cond["type"]
			op    = cond["op"]
			section = cond["section"]
			if isinstance(section, basestring):
				data = data.get(section)
			if data and field in data:
				target_value = str(data[field])
				if dtype == "regex":
					result = re.search(value, target_value) is not None
				elif dtype == "ciexact":
					result = (value.lower() == target_value.lower())
				elif dtype == "exact":
					result = (value == target_value)
				elif dtype == "exact":
					result = (value == target_value)
				elif dtype == "include":
					result = (value in target_value)
				elif dtype == "ciinclude":
					result = (value.lower() in target_value.lower())
				elif dtype.startswith("length"):
					if dtype.endswith("gt"):
						result = (value > len(target_value))
					elif dtype.endswith("lt"):
						result = (value < len(target_value))
					else:
						result = (value == len(target_value))
				else:
					result = None
				if result is None:
					return False
				elif op == "not":
					return not result
				else:
					return result
			return False

		def is_except_condition(each):
			return( "section" in each and
					each.get("op") in (None, "not") and
					isinstance(each.get("field"), basestring) and
					isinstance(each.get("type"),  basestring) and
					isinstance(each.get("value"), basestring) )

		if not(isinstance(conditions, list) and len(conditions) > 0):
			return False
		match_flag = True
		for each in conditions:
			if not is_except_condition(each):
				logger.info("this is corrupt condition config.")
				return False
			elif not is_match(target, each):
				logger.debug("is not matched.")
				logger.debug(str(target))
				logger.debug(str(each))
				match_flag = False
		return match_flag

	def _is_noise(self):
		_sum = self.alert["alert_summary"]
		if _sum:
			return _sum.get("is_noise")
		else:
			return False

	def _check_fp_for_noise(self):
		def _get_hashes(alert):
			result = []
			pslist = alert["alert_detail"].get("process_detail")
			if pslist:
				for eachps in pslist:
					sha256 = eachps.get("ps_hash")
					if isinstance(sha256, basestring):
						result.append(sha256)
			evlist = alert["alert_detail"].get("event_detail")
			if evlist:
				for eachev in evlist:
					ioc_info = eachps.get("ioc_info")
					if ioc_info and ioc_info["type"] == "hash_sha256":
						result.append(ioc_info["value"])
			return list(set(result))

		def _get_nwinfo(alert, field_name):
			result = []
			psgraph = alert["alert_detail"].get("psgraph_info")
			if psgraph:
				for eachgraph in psgraph:
					edge = eachgraph["edge_info"]
					if edge:
						for eachedge in edge:
							infos = eachedge.get(field_name)
							if infos:
								for each in infos:
									pt = r":\d{2,5}$"
									if re.search(pt, each):
										result.append(re.sub(pt, "", each))
									else:
										result.append(each)
			return list(set(result))

		logger.info("check for noise alert.")
		hashlist = _get_hashes(self.alert)
		addrlist = _get_nwinfo(self.alert, "ipaddr")
		hostlist = _get_nwinfo(self.alert, "dns")
		hashresults = self.cyfirma.check_hashes(hashlist)
		addrresults = self.cyfirma.check_domains(hostlist)
		hostresults = self.cyfirma.check_ipv4(addrlist)
		if hashresults:
			self.is_positive = True
			self.is_gray = False
			malhashes = []
			for each in hashresults:
				if isinstance(each["searchvalue"], basestring):
					malhashes.append(each["searchvalue"])
				else:
					malhashes.extend(each["searchvalue"])
			msg = "cyfirmaDetect({})".format(malhashes)
			return None, [ msg ]
		elif addrresults:
			self.is_positive = True
			self.is_gray = True
			maladdrs = []
			for each in addrresults:
				if each.get("searchvalue"):
					if isinstance(each["searchvalue"], basestring):
						maladdrs.append(each["searchvalue"])
					else:
						maladdrs.extend(each["searchvalue"])
				else:
					maladdrs = addrresults
			msg = "cyfirma detect : {}".format(maladdrs)
			return "未", [ msg ]
		elif hostresults:
			self.is_positive = True
			self.is_gray = True
			malhosts = []
			for each in hostresults:
				if each.get("searchvalue"):
					if isinstance(each["searchvalue"], basestring):
						malhosts.append(each["searchvalue"])
					else:
						malhosts.extend(each["searchvalue"])
				else:
					malhosts = hostresults
			msg = "cyfirma detect : {}".format(malhosts)
			return "未", [ msg ]
		else:
			msg = "noise alert and not match IOC."
			self.is_positive = False
			self.is_gray = False
			return "-", [ msg ]

	# TODO followings are deleted after created.
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

