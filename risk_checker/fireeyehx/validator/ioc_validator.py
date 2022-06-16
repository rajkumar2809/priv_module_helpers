# -*- coding: utf-8 -*-

import os, sys
import json, re, glob
from logging import getLogger
from ipaddress import ip_address, IPv6Address

from validator_base import ValidatorBase
from . import TYPECODE_INDICATOR, BLACK, WHITE, GRAY

dirpath = os.path.dirname( os.path.abspath(__file__) )+"/"
apppath = dirpath+"../../"

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

def get_logger(log_name="IOCValidator"):
	return getLogger(log_name)

class IOCValidator(ValidatorBase):
	@classmethod
	def is_target(cls, alert):
		return True # general type is possible to target all alerts

	def __init__(self, alert, validator_config, intel, cyfirma, product, customer, vtapi=None):
		super(IOCValidator, self).__init__(alert, 
				TYPECODE_INDICATOR, get_logger(),
				product=product,    customer=customer,
				cyfirma=cyfirma,    validator_config=validator_config,
				intel=intel,        vtapi=vtapi)
		self.results["process"] = {}
		self.mal_shell_type = 0

	def validate_falsepositive(self):
		for ev in self.alert["alert_detail"]["ioc_detail"]:
			ps_pid  = ev.get("process_id")
			ps_name = ev.get("process_name")
			ps_path = ev.get("process_path")
			if ps_name is None:
				if len(self.alert["alert_detail"]["process_detail"]) is 1:
					eachps = self.alert["alert_detail"]["process_detail"][0]
					ps_pid  = eachps.get("process_id")
					ps_name = eachps.get("process_name")
					ps_path = eachps.get("process_path")
					ev["process_id"] = ps_pid
					ev["process_name"] = ps_name
					ev["process_path"] = ps_path
				else:
					self.is_positive = True
					self.is_gray = False
					self.is_emerg = True
					self.correct_severity = None
					key = "invalid-alert"
					self.results["process"][key] = (BLACK, "invalid alert json object.")
					return #for invalid object
			if isinstance(self.app_map, dict):
				app_name = self._get_app_name(ps_name)
			else:
				app_name = ps_name
			if not isinstance(app_name, basestring):
				app_name = str(app_name)
			search_key = app_name.lower()
			records = self._search_mydb( search_key, "condition" )
			is_match = False
			for rec in records:
				rec_id     = rec.get("id")
				rec_rev    = rec.get("rev")
				reputation = rec.get("reputation")
				message    = rec.get("message")
				detail     = rec.get("detail")
				try:
					is_match = self.fp_check_event_by_each_record(
							ev, ps_name, ps_pid, rec, rec_id, 
							rec_rev, reputation, message, detail)
					if is_match:
						self.logger.info("alert is matched ID:[{}] Rev:[{}]".format(
							rec.get("id"), rec.get("rev")))
						break
				except Exception as e:
					self.logger.error("unknown error at checking record ID:{}".format(rec_id))
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
			self.results["process"][key] = [ flag, message ]
		is_positive = False
		is_black, is_gray = False, False
		for each in self.results.values():
			for v in each.values():
				if v[0] == BLACK:
					is_positive = True
					is_black = True
					break
				elif v[0] == GRAY:
					is_positive = True
					is_gray = True
		self.is_positive = is_positive
		if self.is_positive:
			if is_black:
				severity = None
				self.is_emerg = True
				self.is_gray = False
			elif is_gray:
				severity = "未"
				self.is_gray = True
			else:
				severity = None
				self.is_emerg = True
				self.is_gray = False
		else:
			severity = "-"
		self.correct_severity = severity

	def fp_check_event_by_each_record(self, ev, ps_name, ps_pid,
				rec, rec_id, rec_rev, reputation, message, detail):
		is_match = None
		if not( isinstance(rec_id,  basestring) and
				isinstance(rec_rev, basestring) ):
			self.logger.warning(
					"this record is corrupt. ID:{}".format(rec_id))
			return None
		elif not reputation in ("black", "white", "gray"):
			self.logger.warning(
					"has no correct reputation info [{}]".format(rec))
			return None
		elif not(isinstance(detail, dict) and detail.get("expected")):
			self.logger.warning("record is corrupted. [{}]".format(rec))
			return None
		allconditions = detail["expected"]
		if not(isinstance(allconditions, list)):
			self.logger.warning("record is corrupted. [{}]".format(rec))
			return None
		is_match = True
		for cnd_group in allconditions:
			target, conditions = self._get_match_target(
					cnd_group, ps_name, ps_pid)
			if not(target and conditions):
				self.logger.info(
						"data or conditions are null(or blank).")
				is_match = False
			elif not self._is_match_allcondition(target, conditions):
				self.logger.debug(
						"unmatch condition.")
				is_match = False
		return is_match

	#TODO
	def _get_match_target(self, cnd_group, ps_name, ps_pid):
		if isinstance(cnd_group, dict):
			position = cnd_group.get("data_position")
			conditions = cnd_group.get("conditions")
			if isinstance(position, basestring):
				if position == "event_detail":
					self.logger.debug("data position is event_detail")
					data = self.alert["alert_detail"]["event_detail"]
					data = [] if data is None else data
					for each in data:
						if ps_pid == each.get("process_id") and ps_name == each.get("process_name"):
							return each, conditions
				elif position == "ioc_detail":
					self.logger.debug("data position is ioc_detail")
					data = self.alert["alert_detail"]["ioc_detail"]
					data = [] if data is None else data
					for each in data:
						if ps_pid == each.get("process_id") and ps_name == each.get("process_name"):
							return each, conditions
				elif position == "process_detail":
					self.logger.debug("data position is process_detail")
					data = self.alert["alert_detail"]["process_detail"]
					data = [] if data is None else data
					for each in data:
						if ps_pid == each.get("process_id") and ps_name == each.get("process_name"):
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
				self.logger.info("this is corrupt condition config.")
				return False
			elif not is_match(target, each):
				self.logger.debug("is not matched.")
				match_flag = False
		return match_flag

