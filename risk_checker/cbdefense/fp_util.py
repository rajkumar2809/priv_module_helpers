# -*- coding: utf-8 -*-

import os, sys
import json, re, glob, sre_constants
from monkey_tools.utils import logger_util
#from ipaddress import ip_address, IPv6Address
from validator import WHITE, GRAY, BLACK
from validator.ransomware_validator import RansomwareValidator
from validator.general_validator    import GeneralValidator
from validator.malware_validator    import MalwareValidator, TYPECODE_MALWARE
from validator.hidden_validator     import HiddenValidator
from validator.noise_validator      import NoiseValidator
from validator.blacklist_validator  import CBLValidator

from priv_module_helpers.splunk_helpers import splunk_searcher as _splunk

#import cyfirma_searcher as _cyfirma
from priv_module_helpers.ioc_searcher import main as _ioc_searcher

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
_APP_DIR = CURR_DIR
_CONF_PATH = _APP_DIR   + "/config"
_APP_CONF  = _CONF_PATH + "/application_map.json"
_ADD_CONF  = _CONF_PATH + "/addinfo.json"

_IOC_SPLUNK = "splunk-license01.dhsoc.jp"
_APP_NAME = "fp_checker"

#BLACK = 0xf
#WHITE = 0x0
#GRAY  = 0x8
#WGRAY = 0x1
#BGRAY = 0xe

#ALERT_GENERAL     = 1
#ALERT_RANSOMWARE  = 2
#ALERT_MALWARE_APP = 3

#KEYWORD_RANSOM_DESC = "Ransomware"

#_NOISY_THRESHOLD = 3
#_WHITE_LIST_REPUTATION = [
#	"ADAPTIVE_WHITE_LIST",
#	"COMMON_WHITE_LIST",
#	"COMPANY_WHITE_LIST",
#	"TRUSTED_WHITE_LIST"
#]
#
#_IMPORTANT_THREAT_TAGs = [
#	"FAKE_APP",
#	"REVERSE_SHELL",
#	"KNOWN_BACKDOOR",
#	"KNOWN_DOWNLOADER",
#	"LATERAL_MOVEMENT"
#]
#

def initialize_module():
	MalwareValidator.initialize_module()

class FalsePositiveChecker(object):

	def __init__(self, _id, alert, product, threshold, logger, intel=None, vtapi=None, rm_helper=None):
		with open(_APP_CONF, "r") as f:
			self.app_map = json.load(f)
		with open(_ADD_CONF, "r") as f:
			self.add_conf = json.load(f)
		self.validator_config = { "app_map" : self.app_map, "add_conf" : self.add_conf }
		self.threshold = threshold
		self.id = _id
		self.intel = intel
		self.rm_helper = rm_helper
		self.splunk = _splunk.MySearcher
		if not self.splunk.is_init():
			if "." in _IOC_SPLUNK:
				cfg_name = _IOC_SPLUNK.split(".")[0]
			else:
				cfg_name = _IOC_SPLUNK
			self.splunk.init_splunk_by_cfg_file(cfg_name, app="dhsoc_ioc")
		self.alert = alert
		if "versions" in alert:
			self.version = alert["versions"]
			self.hostname = self.alert["alert_summary"]["hostname"]
			self.customer = alert["alert_src"]["sensor_id"]
		else:
			self.version = None
			self.hostname = self.alert["hostname"]
			self.customer =  alert["cb_appliance_id"]
		self.product = product
		self.is_positive = None
		self.is_gray = False
		self.is_emerg = False
		self.correct_severity = None
		self.mal_shell_type = 0
		self.message = []
		self.results = {
				"network" : {},
				"process" : {},
				"malware" : {}
		}
		self.logger = logger
		_ioc_searcher.logger = logger
		self.set_validator(intel, vtapi)

	def check_fp(self):
		self.logger.info(
				"start fp check -> ID:{} srcHost:{} customer:{}.".format(
					self.id, self.hostname, self.customer) )
		if self.is_blank_alert():
			self.is_positive = False
			self.is_gray = False
			msg = "dont have any detail information. cannot investigation for this alert."
			self.logger.info("{}:{}".format(self.id,msg))
			self.results["process"]["result"] = (WHITE, msg)
		else:
			self.validator.validate_falsepositive()
			self.results     = self.validator.results
			self.is_positive = self.validator.is_positive
			self.is_gray     = self.validator.is_gray
			self.is_emerg    = self.validator.is_emerg
			self.correct_severity = self.validator.correct_severity
			result = self.get_results()

	def get_results(self):
		return {"flag"     : self.is_positive,
				"is_gray"  : self.is_gray,
				"is_emerg" : self.is_emerg,
				"correct_severity" : self.correct_severity,
				"validator_type" : self.get_validator_type(),
				"message": self.get_message()}

	def get_validator_type(self):
		return self.validator.get_type_by_str()

	def is_blank_alert(self):
		ev_details = self.get_event_detail(self.alert)
		return not(self.is_malware_alert()) and len(ev_details) is 0

	def is_malware_alert(self):
		return self.validator.get_type() is TYPECODE_MALWARE

	def set_validator(self, intel, vtapi):
		if "versions" in self.alert:
			alertinfo = self.alert
		else:
			alertinfo = self.alert["alerts"][0]
		if MalwareValidator.is_target(alertinfo):
			self.validator = MalwareValidator(alertinfo,
					validator_config=self.validator_config,
					intel=intel,
					cyfirma=_ioc_searcher.IocChecker(),
					vtapi=vtapi,
					product=self.product,
					rm_helper=self.rm_helper,
					customer=self.customer )
		elif CBLValidator.is_target(alertinfo):
			self.logger.info("Alert:{} is blacklist alert".format(self.id))
			self.validator = CBLValidator(alertinfo,
					validator_config=self.validator_config,
					intel=intel,
					cyfirma=_ioc_searcher.IocChecker(),
					vtapi=vtapi,
					product=self.product,
					rm_helper=self.rm_helper,
					customer=self.customer )
		elif RansomwareValidator.is_target(alertinfo):
			self.logger.info("Alert:{} is ransomware alert".format(self.id))
			self.validator = RansomwareValidator(alertinfo,
					validator_config=self.validator_config,
					intel=intel,
					cyfirma=_ioc_searcher.IocChecker(),
					vtapi=vtapi,
					product=self.product,
					customer=self.customer )
		elif HiddenValidator.is_target(alertinfo):
			self.validator = HiddenValidator(alertinfo,
					validator_config=self.validator_config,
					intel=intel,
					cyfirma=_ioc_searcher.IocChecker(),
					product=self.product,
					customer=self.customer )
		elif NoiseValidator.is_target(alertinfo):
			self.validator = NoiseValidator(alertinfo,
					validator_config=self.validator_config,
					intel=intel,
					cyfirma=_ioc_searcher.IocChecker(),
					product=self.product,
					customer=self.customer )
		else:
			self.logger.info("Alert:{} is general alert".format(self.id))
			self.validator = GeneralValidator(alertinfo,
					validator_config=self.validator_config,
					intel=intel,
					cyfirma=_ioc_searcher.IocChecker(),
					product=self.product,
					customer=self.customer )

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
					self.logger.info( json.dumps(self.results, indent=4) )
					return [ "cannot classified by positive or negative." ]
			else:
				return message

	def get_event_detail(self, incident):
		if "versions" in incident:
			if incident["versions"] == "1.0":
				self.logger.debug("data version is v1.0")
				alert = incident["alert_detail"]
			else:
				assert False, "unknown version"
		else:
			self.logger.debug("no information of data version")
			alert = incident["alerts"][0]
		return alert["threat_app_detail"]

