# -*- coding: utf-8 -*-

import os, sys
import json, re, glob, sre_constants
from monkey_tools.utils import logger_util
from ipaddress import ip_address, IPv6Address
from validator.ioc_validator import IOCValidator
from validator.malware_validator import MalwareValidator
from validator.generic_validator import GenericValidator
from validator.exploit_validator import ExploitValidator
from validator import WHITE, GRAY, BLACK

from priv_module_helpers.splunk_helpers import splunk_searcher as _splunk

#import cyfirma_searcher as _cyfirma
from priv_module_helpers.ioc_searcher import main as _ioc_searcher

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
_APP_DIR = CURR_DIR
_CONF_PATH = _APP_DIR   + "/config"
_APP_CONF  = _CONF_PATH + "/application_map.json"
_VALIDATE_CONF = _CONF_PATH + "/validate_config.json"

_IOC_SPLUNK = "splunk-license01.dhsoc.jp"
_APP_NAME = "fp_checker"

def init_module():
	MalwareValidator.initialize_module()

class FalsePositiveChecker(object):

	def __init__(self, _id, alert, product, threshold, logger, intel=None, vtapi=None, rm_helper=None):
		with open(_APP_CONF, "r") as f:
			self.app_map = json.load(f)
		with open(_VALIDATE_CONF, "r") as f:
			self.validate_conf = json.load(f)
		self.validator_config = { "app_map" : self.app_map, "validate_conf" : self.validate_conf }
		self.threshold = threshold
		self.id = _id
		self.intel = intel
		self.vtapi = vtapi
		self.rm_helper = rm_helper
		self.splunk = _splunk.MySearcher
		if not self.splunk.is_init():
			if "." in _IOC_SPLUNK:
				cfg_name = _IOC_SPLUNK.split(".")[0]
			else:
				cfg_name = _IOC_SPLUNK
			self.splunk.init_splunk_by_cfg_file(cfg_name, app="dhsoc_ioc")
		self.alert = alert
		self.version = alert["versions"]
		self.hostname = self.alert["alert_summary"]["hostname"]
		self.customer = alert["alert_src"]["customer_name"]
		self.product = product
		self.is_positive = None
		self.is_gray = False
		self.is_emerg = False
		self.correct_severity = None
		self.mal_shell_type = 0
		#self.message = []
		self.results = {}
		self.logger = logger
		_ioc_searcher.logger = logger

	def check_fp(self):
		def merge_validator_result(validator1, validator2):
			validator = object()
			validator.results = {}
			validator.results.update(validator1.results)
			validator.results.update(validator2.results)
			validator.is_positive = validator2.is_positive or validator1.is_positive
			validator.is_gray     = validator2.is_gray     or validator1.is_gray
			validator.is_emerg    = validator2.is_emerg    or validator1.is_emerg
			s1 = validator1.correct_severity
			s2 = validator2.correct_severity
			if s1 and s2:
				if "高" in ( s1, s2 ):
					validator.correct_severity = "高"
				elif "中" in ( s1, s2 ):
					validator.correct_severity = "中"
				elif "低" in ( s1, s2 ):
					validator.correct_severity = "低"
				elif "未" in ( s1, s2 ):
					validator.correct_severity = "未"
				elif "-" in ( s1, s2 ):
					validator.correct_severity = "-"
				else:
					validator.correct_severity = None
			elif s1:
				validator.correct_severity = s1
			elif s2:
				validator.correct_severity = s2
			else:
				validator.correct_severity = None
			return validator

		self.logger.info(
				"start fp check -> ID:{} srcHost:{} customer:{}.".format(
					self.id, self.hostname, self.customer) )
		if self.is_blank_alert():
			self.is_positive = False
			self.is_gray = False
			msg = "dont have any detail information. cannot investigation for this alert."
			self.logger.info("{}:{}".format(self.id,msg))
			self.results["process"] = {}
			self.results["process"]["result"] = (WHITE, msg)
		#elif self.has_exploit_alert(): #TODO
		#	severity = "中"
		#	messages = []
		#	for each in self.alert["alert_detail"]["exploit_detail"]:
		#		each_msg = "{}({})".format(
		#			str(each["exploit_type"]), str(each["process_name"]))
		#		messages.append(each_msg)
		#		if not each.get("is_blocked") == "no":
		#			severity ="高"
		#	self.results["process"] = {}
		#	self.results["process"]["result"] = ( BLACK, ", ".join(messages) )
		#	self.is_positive = True
		#	self.is_gray     = False
		#	self.is_emerg    = True
		#	self.correct_severity = severity
		else:
			if self.has_malware_alert():
				self.logger.info("this event is detected by AntiVirus.")
				mal_validator = MalwareValidator(self.alert,
						validator_config=self.validator_config,
						intel=self.intel,
						cyfirma=_ioc_searcher.IocChecker(),
						vtapi=self.vtapi,
						product=self.product,
						rm_helper=self.rm_helper,
						customer=self.customer )
				mal_validator.validate_falsepositive()
			else:
				mal_validator = None
			if self.has_ioc_alert():
				self.logger.info("this event is detected by IOC.")
				ioc_validator = IOCValidator(self.alert,
						validator_config=self.validator_config,
						intel=self.intel,
						cyfirma=_ioc_searcher.IocChecker(),
						vtapi=self.vtapi,
						product=self.product,
						customer=self.customer )
				ioc_validator.validate_falsepositive()
			else:
				ioc_validator = None
			if self.has_exploit_alert():
				self.logger.info("this event is detected by Exploit.")
				exploit_validator = ExploitValidator(self.alert,
						validator_config=self.validator_config,
						intel=self.intel,
						cyfirma=_ioc_searcher.IocChecker(),
						vtapi=self.vtapi,
						product=self.product,
						customer=self.customer )
				exploit_validator.validate_falsepositive()
			else:
				exploit_validator = None
			if self.has_generic_alert():
				self.logger.info("this event is detected by Generic.")
				generic_validator = GenericValidator(self.alert,
						validator_config=self.validator_config,
						intel=self.intel,
						cyfirma=_ioc_searcher.IocChecker(),
						vtapi=self.vtapi,
						product=self.product,
						customer=self.customer )
				generic_validator.validate_falsepositive()
			else:
				generic_validator = None
			if mal_validator is None:
				validator = ioc_validator
			elif ioc_validator is None:
				validator = mal_validator
			else:
				validator = merge_validator_result(mal_validator, ioc_validator)
			if exploit_validator:
				if validator is None:
					validator = exploit_validator
				else:
					validator = merge_validator_result(validator, exploit_validator)
			if generic_validator:
				if validator is None:
					validator = generic_validator
				else:
					validator = merge_validator_result(validator, generic_validator)
			self.results     = validator.results
			self.is_positive = validator.is_positive
			self.is_gray     = validator.is_gray
			self.is_emerg    = validator.is_emerg
			self.correct_severity = validator.correct_severity

	def has_generic_alert(self):
		details = self.alert["alert_detail"].get("generic_detail")
		if details:
			return len(details) > 0
		else:
			return False

	def has_ioc_alert(self):
		details = self.alert["alert_detail"]["ioc_detail"]
		if details:
			return len(details) > 0
		else:
			return False

	def has_malware_alert(self):
		details = self.alert["alert_detail"]["malware_detail"]
		if details:
			return len(details) > 0
		else:
			return False

	def has_exploit_alert(self):
		details = self.alert["alert_detail"]["exploit_detail"]
		if details:
			return len(details) > 0
		else:
			return False

	def is_blank_alert(self):
		ev_details = self.alert["alert_detail"]["event_detail"]
		if ev_details:
			return len(ev_details) is 0
		else:
			return True

	def get_message(self):
		message = []
		if self.results.get("malware"):
			try:
				message.append("sha256,severity,referenced")
				for each in self.results["malware"]["result"]:
					message.append("{}:{}:{}. Detail is Followings.\n{}\n".format(
						each["hash"], each["severity"], each["ticket_id"],
						each["message"]))
				return message
			except Exception as e:
				self.logger.info("check result is invalid")
				self.logger.exception(e)
				return [ self.results["malware"]["result"] ]
		else:
			pos_flags = (GRAY, BLACK)
			for each in self.results.values():
				for k, v in each.items():
					if self.is_positive and v[0] in pos_flags:
						message.append({"ppid": k , "message" : v[1]})
					elif not self.is_positive and v[0] == WHITE:
						message.append({"ppid": k , "message" : v[1]})
			if len(message) is 0:
				if self.alert["alert_summary"]["is_noise"]:
					return [ "noise alert and dont detect by IOC." ]
				else:
					return [ "cannot classified by positive or negative." ]
			else:
				return message

