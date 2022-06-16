# -*- coding: utf-8 -*-

import os, sys
import json, re, glob
from logging import getLogger
from ipaddress import ip_address, IPv6Address
from validator_base import ValidatorBase
from validator.general_validator import GeneralValidator
from validator.malware_validator import MalwareValidator
from . import TYPECODE_BLACKLIST, BLACK, WHITE, GRAY

dirpath = os.path.dirname( os.path.abspath(__file__) )+"/"
apppath = dirpath+"../../"

def get_logger(log_name="CBLValidator"):
	return getLogger(log_name)

class CBLValidator(ValidatorBase):
	@classmethod
	def is_target(cls, alert):
		if alert.get("alert_summary"):
			alert_type = alert["alert_summary"].get("alert_type")
			return alert_type == "blacklist"
		else:
			return False

	def __init__(self, alert, validator_config, intel, cyfirma, product, customer, vtapi, rm_helper):
		super(CBLValidator, self).__init__(alert, 
				TYPECODE_BLACKLIST, get_logger(),
				product=product,    customer=customer,
				cyfirma=cyfirma,    validator_config=validator_config,
				intel=intel,        vtapi=vtapi,
				rm_helper=rm_helper)
		self.malware_validator = MalwareValidator(alert,
				validator_config=validator_config,
				intel=intel,
				cyfirma=cyfirma,
				vtapi=vtapi,
				product=product,
				rm_helper=rm_helper,
				customer=customer )
		self.general_validator = GeneralValidator(alert,
				validator_config=validator_config,
				intel=intel,
				cyfirma=cyfirma,
				vtapi=vtapi,
				product=product,
				customer=customer )
		self.validator = None
		#self.results["network"] = {}
		#self.results["process"] = {}
		#self.results["malware"] = {}
		#self.mal_shell_type = 0

	def validate_falsepositive(self):
		self.logger.info("check for blacklist alert.")
		self.malware_validator.validate_falsepositive()
		if self.malware_validator.is_emerg:
			self.is_positive = self.malware_validator.is_positive
			self.is_gray = self.malware_validator.is_gray
			self.is_emerg = self.malware_validator.is_emerg
			self.results = self.malware_validator.results
			self.correct_severity = self.malware_validator.correct_severity
			self.validator = self.malware_validator
		else:
			self.general_validator.validate_falsepositive()
			self.is_positive = self.general_validator.is_positive
			self.is_gray = self.general_validator.is_gray
			self.is_emerg = self.general_validator.is_emerg
			self.results = self.general_validator.results
			self.correct_severity = self.general_validator.correct_severity
			self.validator = self.general_validator

	def get_type_by_str(self):
		return self.validator.get_type_by_str()

