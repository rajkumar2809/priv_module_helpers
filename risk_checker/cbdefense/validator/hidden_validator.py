# -*- coding: utf-8 -*-

import os, sys
import json, re, glob
from ipaddress import ip_address, IPv6Address
from logging import getLogger

from validator_base import ValidatorBase
from . import TYPECODE_HIDDEN, BLACK, WHITE, GRAY

dirpath = os.path.dirname( os.path.abspath(__file__) )+"/"
apppath = dirpath+"../../"

def get_logger(log_name="HiddenValidator"):
	return getLogger(log_name)

class HiddenValidator(ValidatorBase):

	@classmethod
	def is_target(cls, alert):
		if "versions" in alert:
			_reason = alert["alert_detail"]["threat_cause_reason"].lower()
			return _reason == "r_hidden"
		return False

	def __init__(self, alert,
			product=None, customer=None, cyfirma=None, validator_config=None,
			intel=None, vtapi=None):
		super(HiddenValidator, self).__init__(alert, 
				TYPECODE_HIDDEN, get_logger(),
				product=product,  customer=customer,
				cyfirma=cyfirma,  validator_config=validator_config,
				intel=intel,      vtapi=vtapi)
		self.results["process"] = {}

	def validate_falsepositive(self):
		self.logger.info( "start to FP check at hidden_process alert." )
		msg = ""
		customer_name = self.alert["alert_src"]["customer_name"]
		ev_detail = self.alert["alert_detail"].get("threat_cause_event_detail")
		nw_access = self._get_nw_access(self.alert)
		if ev_detail:
			apps = "Select:{}({}), Parent:{}({})".format(
				ev_detail["select_app"].get("applicationName"),
				ev_detail["select_app"].get("reputationProperty"),
				ev_detail["parent_app"].get("applicationName"),
				ev_detail["parent_app"].get("reputationProperty")
			)
			if( self._is_trust_app(ev_detail["parent_app"]) and
				self._is_trust_app(ev_detail["select_app"]) ):
				self.logger.info("parent and select app are trusted")
				self.is_gray = False
				self.is_positive = False
				msg = "HiddenProcess and parent are Trusted. {}".format(apps)
				self.results["process"]["result"]=(WHITE, msg)
			else:
				self.logger.info("parent or select app is not trusted")
				detected, cy_res = self._check_cyfirma_nw_dst(nw_access)
				if detected:
					self.logger.info("hidden process is malicious.")
					self.is_positive = True
					self.is_gray = False
					msg = str(cy_res)
					self.results["process"]["cyfirma"] = (BLACK, msg)
				else:
					self.logger.info("hidden process is not detected by cyfirma.")
					self.is_positive = False
					self.is_gray = False
					msg = "hidden process without detected cyfirma IOC."
					self.results["process"]["result"]=(WHITE, msg)
		else:
			self.is_gray = True
			self.is_positive = True
			msg =  "cannot check event detail."
			self.logger.info(msg)
			self.results["process"]["result"] = (GRAY, msg)
	
	# private

	def _is_trust_app(self, app_info):
		rep = app_info.get("reputationProperty")
		if rep:
			return (app_info["reputationProperty"]=="TRUSTED_WHITE_LIST"
					or
					app_info["reputationProperty"]=="COMPANY_WHITE_LIST")
		else:
			return False

