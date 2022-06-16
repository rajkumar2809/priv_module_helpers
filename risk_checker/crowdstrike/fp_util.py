# -*- coding: utf-8 -*-

import os, sys
import json, re, glob, sre_constants
from monkey_tools.utils import logger_util
from ipaddress import ip_address, IPv6Address
from validator.malware_validator import MalwareValidator
from validator.general_validator import GeneralValidator

from priv_module_helpers.splunk_helpers import splunk_searcher as _splunk

#import cyfirma_searcher as _cyfirma
from priv_module_helpers.ioc_searcher import main as _ioc_searcher

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
_APP_DIR = CURR_DIR
_CONF_PATH = _APP_DIR+"/config"
_APP_CONF = _CONF_PATH+"/application_map.json"
_ADD_CONF = _CONF_PATH+"/addinfo.json"

with open(_APP_CONF) as f:
	application_map = json.load(f)

_IOC_SPLUNK = "splunk-license01.dhsoc.jp"

BLACK = 0xf
WHITE = 0x0
GRAY  = 0x8
WGRAY = 0x1
BGRAY = 0xe

ALERT_GENERAL     = 1
ALERT_RANSOMWARE  = 2
ALERT_MALWARE_APP = 3

KEYWORD_RANSOM_DESC = "Ransomware"
_APP_NAME = "fp_checker"

_NOISY_THRESHOLD = 3
_WHITE_LIST_REPUTATION = [
	"ADAPTIVE_WHITE_LIST",
	"COMMON_WHITE_LIST",
	"COMPANY_WHITE_LIST",
	"TRUSTED_WHITE_LIST"
]

_IMPORTANT_THREAT_TAGs = [
	"FAKE_APP",
	"REVERSE_SHELL",
	"KNOWN_BACKDOOR",
	"KNOWN_DOWNLOADER",
	"LATERAL_MOVEMENT"
]

class FalsePositiveChecker(object):

	def __init__(self, _id, alert, product, logger, intel=None, vtapi=None, rm_helper=None):
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
		self.version = alert["versions"]
		self.customer = alert["alert_src"]["customer_name"]
		self.product = product
		self.is_positive = None
		self.is_gray = False
		self.correct_severity = None
		self.mal_shell_type = 0
		self.results = {
				"network" : {},
				"process" : {},
				"malware" : {}
		}
		self.logger = logger
		with open(_APP_CONF) as f:
			self.app_map = json.load(f)
		_ioc_searcher.logger = logger
		self.set_validator(intel, vtapi)
	
	def check_fp(self):
		"""
		TODO: only general alert type currently.
		TODO: this method will be move to FPCheckMgr
		"""
		hostname = self.alert["alert_summary"]["hostname"]
		self.logger.info(
				"start fp check -> ID:{} srcHost:{}.".format(
					self.id, hostname) )
		severity, results = self.validator.validate_falsepositive()
		if severity is None:
			self.is_positive = True
		else:
			self.correct_severity = severity
			if severity == "-":
				self.is_positive = False
			elif severity == "未":
				self.is_positive = True
				self.is_gray = True
			else:
				self.is_positive = True
		self.results = results

	def set_validator(self, intel, vtapi):
		alertinfo = self.alert
		if MalwareValidator.is_target(alertinfo):
			self.logger.info("Alert:{} is malware alert".format(self.id))
			self.validator = MalwareValidator(alertinfo,
					product=self.product, intel=intel, vtapi=vtapi,
					cyfirma=_ioc_searcher.IocChecker(), rm_helper=self.rm_helper)
		else:
			self.logger.info("Alert:{} is general alert".format(self.id))
			self.validator = GeneralValidator(alertinfo,
					product=self.product, intel=intel, vtapi=vtapi,
					app_map=application_map, 
					cyfirma=_ioc_searcher.IocChecker())

	def get_message(self):
		if MalwareValidator.is_target(self.alert):
			return self.validator.get_message()
		else:
			return self.results

