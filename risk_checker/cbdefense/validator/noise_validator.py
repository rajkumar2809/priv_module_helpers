# -*- coding: utf-8 -*-

import os, sys
import json, re, glob
from logging import getLogger
from ipaddress import ip_address, IPv6Address
from validator_base import ValidatorBase
from . import TYPECODE_NOISE, BLACK, WHITE, GRAY

dirpath = os.path.dirname( os.path.abspath(__file__) )+"/"
apppath = dirpath+"../../"

_NOISY_THRESHOLD = 3

def get_logger(log_name="GeneralValidator"):
	return getLogger(log_name)

class NoiseValidator(ValidatorBase):
	@classmethod
	def is_target(cls, alert):
		if "is_noise" in alert["alert_summary"]:
			return alert["alert_summary"]["is_noise"]
		else:
			return False

	def __init__(self, alert, validator_config, intel, cyfirma, product, customer, vtapi=None):
		super(NoiseValidator, self).__init__(alert, 
				TYPECODE_NOISE,  get_logger(),
				product=product, customer=customer,
				cyfirma=cyfirma, validator_config=validator_config,
				intel=intel,     vtapi=vtapi)
		self.results["network"] = {}
		self.results["process"] = {}
		self.mal_shell_type = 0

	def validate_falsepositive(self):
		self.logger.info("check for noise alert.")
		ev_details = self._get_event_detail(self.alert)
		nw_access = self._get_nw_access(self.alert)
		detected, cy_res = self._check_cyfirma_hash(ev_details)
		if detected:
			self.is_emerg = True
			self.is_positive = True
			self.is_gray = False
			for each in cy_res:
				self.results["process"][each["hash"]] = (BLACK, "CyFirmaDetected({})".format(each["name"]))
			return
		detected, cy_res = self._check_cyfirma_nw_dst(nw_access)
		if detected:
			self.is_positive = True
			self.is_gray = True
			for each in cy_res:
				self.results["network"][each["searchvalue"]] = (BLACK, "CyFirmaDetected({})".format(each["searchvalue"]))
			return
		else:
			self.is_positive = False
			self.is_gray = False


