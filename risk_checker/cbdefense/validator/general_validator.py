# -*- coding: utf-8 -*-

import os, sys
import json, re, glob, sre_constants
from logging import getLogger
#from ipaddress import ip_address, IPv6Address

from validator_base import ValidatorBase, _IMPORTANT_THREAT_TAGs
from . import TYPECODE_GENERAL, BLACK, WHITE, GRAY

dirpath = os.path.dirname( os.path.abspath(__file__) )+"/"
apppath = dirpath+"../../"

_NOISY_THRESHOLD = 3
_WHITE_LIST_REPUTATION = [
	"ADAPTIVE_WHITE_LIST",
	"COMMON_WHITE_LIST",
	"COMPANY_WHITE_LIST",
	"TRUSTED_WHITE_LIST"
]

def get_logger(log_name="GeneralValidator"):
	return getLogger(log_name)

class GeneralValidator(ValidatorBase):
	@classmethod
	def is_target(cls, alert):
		return True # general type is possible to target all alerts

	def __init__(self, alert, validator_config, intel, cyfirma, product, customer, vtapi=None):
		super(GeneralValidator, self).__init__(alert, 
				TYPECODE_GENERAL, get_logger(),
				product=product,  customer=customer,
				cyfirma=cyfirma,  validator_config=validator_config,
				intel=intel,      vtapi=vtapi)
		self.results["network"] = {}
		self.results["process"] = {}
		self.results["cyfirma"] = {} #TODO
		self.appname_list = {}
		for ppid, info in self._get_application_name_list().items():
			self.appname_list[ppid] = info
		self.details = {
			"product"        : "carbonblack",
			"customer_name"  : self.alert["alert_src"]["customer_name"],
			"validator"      : "general_validator",
			"is_except"      : self.alert["alert_summary"].get("is_except"),
			"base_severity"  : self.alert["alert_summary"]["severity"],
			"alert_level"    : self.alert["alert_summary"]["alert_level"],
			"global_access"  : self._get_global_access(),
			"nw_listen"      : self._has_listen_port(),
			"important_tags" : self._get_important_tags(),
			"shelltype_of_malprocess"   : 0,
			"cyfirma_detected_by_hash"  : [],
			"cyfirma_detected_by_nwdst" : [],
			"malicious_process"         : {} }

	def validate_falsepositive(self):
		# check each process(nw_dst) is malicious or not
		self._check_fp_for_general()

		# judge results of checking
		self._judge_fpcheck_result_1st()
		## TODO:for testing
		#_id = self.alert["alert_summary"]["alert_id"]
		#with open("/tmp/test/{}.json".format(_id), "w") as wf:
		#	json.dump(self.details, wf, indent=4)
		if self.is_positive:
			self._judge_fpcheck_result_2nd()
		else:
			self.logger.debug("this is false positive.")
	
	def _judge_fpcheck_result_1st(self):
		if self._has_black_reputation_process():
			self.is_emerg    = True
			self.is_positive = True
			self.is_gray     = False
		elif self._is_white_at_all():
			self.is_emerg    = False
			self.is_positive = False
			self.is_gray     = False
		elif self._is_fp_cause_event():
			self.logger.info("alert main process is FalsePositive.")
			self.is_emerg    = False
			self.is_positive = True
			self.is_gray     = True
		elif self._is_noisy() and self._by_whitelist_app():
			self.logger.info("noisy events and Source Process is WHITELISTED.")
			self.is_emerg    = False
			self.is_positive = True
			self.is_gray     = True
		else:
			self.logger.info("this alert is positive and not emerg.")
			self.is_emerg    = False
			self.is_positive = True
			self.is_gray     = False

	def _judge_fpcheck_result_2nd(self):
		mal_shell_type = 0
		for each in self.details["malicious_process"].values():
			if each["flags"]["positive"]:
				if mal_shell_type < each["shell_type"]:
					mal_shell_type = each["shell_type"]
		#if mal_shell_type is 5:
		#	self.logger.debug("have event by powershell/shellscript. need to check detail by analyst..")
		#elif mal_shell_type > 0 and self.details["global_access"]:
		#	self.logger.debug("has shell event and global ip access. need to check detail by analyst..")
		#elif mal_shell_type is 0 and not self.is_gray and not self.details["base_severity"] == "低":
		#	self.logger.debug("unshellProcess(type=0) and is_gray:{}, severity:{}".format(self.is_gray, self.details["base_severity"]))
		##if self._is_need_next_check(nw_access):
		if self.details["cyfirma_detected_by_nwdst"]:
			cy_res = self.details["cyfirma_detected_by_nwdst"]
			try:
				for each in cy_res:
					searchvalue = str(each["searchvalue"])
					message = "IOCDetected({}:{})".format(
							str(each["ioc_source"]), str(each["ioc_type"]))
					self.results["cyfirma"][searchvalue] = (BLACK, message)
			except Exception as e:
				self.logger.error(e.message)
				self.logger.exception(e)
				self.results["cyfirma"][str(cy_res)] = (
						BLACK, "detected by IOC but data is corrupted")
		elif self.details["is_except"] and not self.details["base_severity"] == "低":
			self.is_emerg = True #TODO:add 210929
			if self.alert["alert_summary"]["alert_type_desc"]:
				reason = self.alert["alert_summary"]["alert_type_desc"]
			else:
				reason = self.alert["alert_summary"]["alert_type"]
			self.results["process"]["ALERT_SUMMARY"] = (BLACK, reason)
		elif self.details["important_tags"]:
			################
			#TODO:add 210929
			if self.is_gray:
				self.is_gray=False
			elif self.details["global_access"]:
				self.is_emerg = True 
			################
			tags = [ each["tag"] for each in self.details["important_tags"] ]
			reason = "Has Important Threat Tag of {}".format( ",".join(tags) )
			self.logger.info("important tags exist. {}".format(reason))
			self.results["process"]["ALERT_SUMMARY"] = (BLACK, str(reason))
		else:
			self.is_positive = False
			self.is_gray = False
			self.results["process"]["ALERT_SUMMARY"] = (
				WHITE, "is noise alert and not detected by IOC.")

	def _check_fp_for_general(self):
		# check by  IOC only
		detected, result = self._check_cyfirma_hash()
		self.details["cyfirma_detected_by_hash"] = result
		detected, result = self._check_cyfirma_nw_dst()
		self.details["cyfirma_detected_by_nwdst"] = result

		ev_details = self._get_event_detail(self.alert)
		if self.details["cyfirma_detected_by_hash"]:
			self.is_emerg = True
			self.is_positive = True
			self.is_gray = False
			for each in self.details["cyfirma_detected_by_hash"]:
				phash = each["hash"]
				pname = each["name"]
				msg = "CyFirmaDetected({}:{})".format(pname, phash)
				self.results["process"][phash] = (BLACK, msg)
				pslist = self._get_psinfo_by_hash(phash)
				if pslist:
					for eachps in pslist:
						ppid = eachps["process_info"]["ppid"]
						app_name = self.appname_list[ppid]["name"]
						self.details["malicious_process"][ppid] = {
							"flags" : { "cyfirma"  : True,
										"positive" : True,
										"gray"     : False,
										"main"     : self._is_main_process(ppid),
										"emerg"    : True },
							"shell_type" : self._get_shell_type(app_name),
							"app_name"   : app_name,
							"message"    : msg,
							"details"    : eachps }
				else:
					self.details["malicious_process"][phash] = {
						"flags" : { "cyfirma"  : True,
									"positive" : True,
									"gray"     : False,
									"main"     : False,
									"emerg"    : True },
						"shell_type" : 0,
						"app_name"   : "N/A",
						"message"    : msg,
						"details"    : each }
			return
		for each in ev_details:
			ppid = each["process_info"]["ppid"]
			app_name = self.appname_list[ppid]["name"]
			if not ppid in self.details["malicious_process"]:
				flag, message = self._check_application(each)
				shell_type = self._get_shell_type(app_name)
				is_positive = flag != WHITE
				self.results["process"][ppid]=(flag, message)
				self.details["malicious_process"][ppid] = {
					"flags" : { "cyfirma"  : False,
								"main"     : self._is_main_process(ppid),
								"positive" : is_positive,
								"gray"     : flag == GRAY,
								"emerg"    : flag == BLACK },
					"shell_type" : shell_type,
					"app_name"   : app_name,
					"message"    : message,
					"details"    : each }

	def _check_application(self, info):
		ps_info  = info["process_info"]
		ppid     = ps_info["ppid"]
		app_hash = ps_info["hash"]
		app_name = self.appname_list[ppid]["name"]

		self.logger.info("check risk at hash:{}".format( app_hash ))
		records = self._search_mydb( app_hash, "hash" )
		for each in records:
			if self.is_black(each):
				return BLACK, "{}:{}".format(app_hash, each["message"])
			elif self.is_white(each):
				return WHITE, "{}:{}".format(app_hash, each["message"])

		mal_events = self.get_malicious_events(info["events"])
		if len(mal_events) is 0:
			self.logger.info( u"application:{} has no malicious events".format(app_name) )
			if self.alert["alert_summary"].get("is_except"):
				self.logger.info("this alert is except alert type.")
				return BLACK, "ThisIsExceptTypeAlert:{}".format(self.alert["alert_summary"].get("alert_type_desc"))
			else:
				return WHITE, "{}({}):has no malicious event".format(app_name, ps_info["pid"])

		#flag, message = GRAY, "{}:not classified positive or negative".format(app_hash)
		self.logger.info("application:{} malicious events num:{}.".format(
			app_name, len(mal_events)) )
		return self.check_psinfo_is_safe(app_name, ps_info, mal_events)

	def check_psinfo_is_safe(self, app_name, ps_info, mal_events):
		def split_by_data_position( records ):
			rec_ev = []
			rec_ps = []
			for each in records:
				if not each.has_key("detail"):
					continue
				detail = each["detail"]
				if not detail.has_key("data_position"):
					continue
				elif detail["data_position"].lower() == "events":
						rec_ev.append(each)
				else:
						rec_ps.append(each)
			return rec_ev, rec_ps

		def is_fp_by_mal_events(mal_events, white_events):
			msg_white=[]
			msg_gray =[]
			total_flag = True
			for each in mal_events:
				flag, rec_id, rec_msg = self.is_whitelisted(each, white_events)
				if flag:
					msg_white.append("{}:<{}>".format(rec_id, rec_msg))
				else:
					self.logger.debug( "event is not whitelisted. {}".format(json.dumps(each)) )
					msg_gray.append("{}:<{}>".format(rec_id, rec_msg))
					total_flag = False
			if total_flag:
				return total_flag, msg_white
			else:
				return total_flag, msg_gray

		def is_fp_by_psinfo(ps_info, pid, white_psinfos):
			flag, rec_id, rec_msg = self.is_whitelisted(ps_info, white_psinfos)
			if flag:
				return True, "{}({}):{}:<{}>".format(app_name, pid, rec_id, rec_msg)
			self.logger.debug( "process information is not whitelisted. {}".format(json.dumps(ps_info)) )
			return False, ""

		pid = ps_info["pid"]
		self.logger.debug( u"checkFP by event:{} {}".format( app_name, pid ) )
		records = self._search_mydb( app_name, "condition" )
		self.logger.debug("record num:{} app_name:{}".format(len(records), app_name))
		if len(records) is 0:
			return GRAY, "{}({}):no records found.".format(app_name, pid)
		white_events, white_psinfos = split_by_data_position( records )
		flag, msg = is_fp_by_psinfo( ps_info, pid, white_psinfos )
		if flag:
			return WHITE, msg

		flag, msg = is_fp_by_mal_events(mal_events, white_events)
		if flag:
			return WHITE, "{}({}):[{}]".format(app_name, pid, "||".join(msg))

		# check by count matching events.
		return GRAY, "{}({}):has un-whitelisted mal event.".format(app_name, pid)
	
	def is_whitelisted(self, data, records):
		self.logger.debug("registered record num:{}.".format(len(records)))
		counters = {}
		for each_record in records:
			try:
				flag, rec_id, rec_msg = self.is_each_whitelisted(data, each_record)
				if flag:
					return flag, rec_id, rec_msg
			except KeyError as e:
				self.logger.error( "KeyError[{}] of splunk records[{}].".format(e.message, each_record["id"]) )
			except sre_constants.error as e:
				self.logger.error( "RegExError[{}] of splunk records[{}].".format(e.message, each_record["id"]) )
		return False, "", ""
	
	def is_each_whitelisted(self, data, record):
		"""
		@param data log data for checking match the records
		@param records white listed records in private database.
		@return <bool> True is exist(whitelisted).
		@return <str> id of records at matching entry. if no match, return blank string.
		@return <str> message of records at matching entry. if no match, return blank string.
		"""
		def is_match(value, target, vtype):
			vtype = vtype.lower()
			if vtype == "exact":
				return value == target
			elif vtype == "ciexact":
				return value.lower() == target.lower()
			elif vtype == "include":
				return value in target
			elif vtype == "regexp":
				return re.search(value, target) is not None
			elif vtype == "neq":
				return not(value == target)
			elif vtype == "exclude":
				return not(value in target)

		def get_need_info_in_record(record):
			field = record["field"]
			value = record["value"]
			vtype = record["type" ]
			return field, value, vtype

		is_all_match = True
		for each in record["detail"]["expected"]:
			field, value, vtype = get_need_info_in_record(each)
			target = data[field]
			if target and not is_match(value, target, vtype):
				is_all_match = False

		if is_all_match:
			return True, record["id"], record["message"]
		else:
			return False, "", ""

	def get_malicious_events(self, events, include_nw_event=False):
		results = []
		for each in events:
			if each['ev_type'] == "NETWORK_ACCESS" and not include_nw_event:
				continue
			elif each['attack_phase'] and len(each['attack_phase']) is not 0:
				results.append(each)
		return results

	def _get_ppid_by_event_id(self, event_id):
		for each in self.alert["alert_detail"]["threat_app_detail"]:
			for ev in each["events"]:
				idlist = ev["event_id"]
				if event_id in idlist:
					return each["process_info"]["ppid"]
		return None

	def _is_noisy(self):
		summary = self.alert["alert_summary"]
		if "noisy_level" in summary:
			return summary["noisy_level"] >= _NOISY_THRESHOLD
		else:
			return False

	def _by_whitelist_app(self):
		def is_whitelisted(app):
			rep = app["reputationProperty"]
			return rep in _WHITE_LIST_REPUTATION
		if "threat_cause_event_detail" in self.alert["alert_detail"]:
			ev_detail = self.alert["alert_detail"]["threat_cause_event_detail"]
			if ev_detail and "event_info" in ev_detail:
				return( is_whitelisted( ev_detail["parent_app"] ) and
						is_whitelisted( ev_detail["select_app"] ) and
						is_whitelisted( ev_detail["target_app"] ) )
		return False

	def is_white( self, record ):
		"""
		@param record<dict<unfixed type>> record info in private database.
		@return <bool> True : reputation value is white.(case insensitive)
		"""
		keyname = "reputation"
		value = "white"
		if record.has_key(keyname):
			return record[keyname].lower() == value
		else:
			return False

	def is_black( self, record ):
		"""
		@param record<dict<unfixed type>> record info in private database.
		@return <bool> True : reputation value is black.(case insensitive)
		"""
		keyname = "reputation"
		value = "black"
		if record.has_key(keyname):
			return record[keyname].lower() == value
		else:
			return False
	
	def _get_application_name_list(self):
		results = {}
		for each in self._get_event_detail(self.alert):
			ppid    = each["process_info"]["ppid"]
			ps_path = each["process_info"]["path"]
			if isinstance(ps_path, basestring):
				try:
					ps_path = ps_path.encode("utf-8").decode()
				except:
					self.logger.info(
							"undecode filename. replace to <RepChar>")
					word = ""
					for each in ps_path:
						try:
							word += each.encode("utf-8").decode()
						except:
							word += "<RepChar>"
					ps_path = word
					self.logger.info("replaced filename:{}.".format(ps_path))
			elif ps_path is None:
				ps_path = "nullapplication_path"
			else:
				ps_path = str(ps_path)
			app_name = self._get_app_name( ps_path )
			results[ppid] = { "name" : app_name }
		return results

	def _get_psinfo_by_hash(self, phash):
		result = []
		ev_details = self._get_event_detail(self.alert)
		for each in ev_details:
			psinfo = each["process_info"]
			if phash == psinfo["hash"] or phash == psinfo["parent_hash"]:
				result.append(each)
		return result

	def _has_black_reputation_process(self):
		for each in self.details["malicious_process"].values():
			flags = each["flags"]
			if flags["positive"] and flags["emerg"]:
				return True
		return False

	def _is_white_at_all(self):
		is_white = False
		for each in self.details["malicious_process"].values():
			flags = each["flags"]
			if flags["positive"]:
				return False
			else:
				is_white = True
		return is_white

	def _is_fp_cause_event(self):
		for each in self.details["malicious_process"].values():
			flags = each["flags"]
			if flags["main"]:
				return not(flags["positive"])
		return False # cause event not exists in events


