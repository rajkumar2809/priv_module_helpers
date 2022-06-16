import sys, os
import re, json
from time import mktime
from datetime import datetime
from validate_const import VtValidatorConst as const_v

# AGRESSIVE > MEDIUM > CERTAINTY

_REASON_ = const_v.Reason
_KEY_    = const_v.KEY
_TYPE_   = const_v.Result
_DEF_    = const_v.Default

class HashValidator(object):
	def __init__(self, use_default=True):
		self.condition = {}
		self.init_vendors()
		if use_default:
			self._to_default_condition()

	def init_vendors(self, lv1_vendors=None, lv2_vendors=None):
		self.lv1_vendors = []
		self.lv2_vendors = []
		if lv1_vendors:
			assert hasattr(lv1_vendors, "__iter__"), "lv1_vendors must be iterable type"
			for each in lv1_vendors:
				self.add_vendors(_KEY_.Lv1, each)
		else:
			for each in _DEF_.LV1_VENDORS_KEYWORD:
				self.add_vendors(_KEY_.Lv1, each)
		if lv2_vendors:
			assert hasattr(lv2_vendors, "__iter__"), "lv2_vendors must be iterable type"
			for each in lv2_vendors:
				self.add_vendors(_KEY_.Lv2, each)
		else:
			for each in _DEF_.LV2_VENDORS_KEYWORD:
				self.add_vendors(_KEY_.Lv2, each)
	
	def clear_vendors(self, vendor_type):
		if vendor_type == _KEY_.Lv1:
			self.lv1_vendors = []
		elif vendor_type == _KEY_.Lv2:
			self.lv2_vendors = []
		else:
			assert False, "vendor_type is acceptable only lv1 or lv2 with str type"

	def add_vendors(self, vendor_type, value):
		assert isinstance(value, str) or isinstance(value, unicode), "vendor name is only acceptable str type"
		if vendor_type == _KEY_.Lv1:
			self.lv1_vendors.append(value)
		elif vendor_type == _KEY_.Lv2:
			self.lv2_vendors.append(value)
		else:
			assert False, "vendor_type is acceptable only lv1 or lv2 with str type"

	def get_condition(self):
		return self.condition

	def set_condition_for_suspicious(self, base, detected_score):
		self._set_condition(
				base, _TYPE_.SUSPICIOUS,
				detected_score=detected_score.copy())

	def set_condition_for_malicious(self, base, detected_score):
		self._set_condition(
				base, _TYPE_.MALICIOUS, 
				detected_score=detected_score.copy())

	def validate(self, target):
		self._check_target_is_valid(target)
		info = self._get_validate_info(target) 
		score, reason, detected_point = self._calc_risk(info)
		return {
				"value"       : target["hash"],
				"score"       : score,
				"reputation"  : self._get_reputation(score),
				"reason_code" : reason[0],
				"reason"      : reason[1],
				"detected_point" : detected_point }

###### private #######

	def _get_reputation(self, score):
		if score is _TYPE_.MALICIOUS:
			return "malicious"
		elif score is _TYPE_.SUSPICIOUS:
			return "suspicious"
		elif score is _TYPE_.GOOD:
			return "benign"
		else:
			return "unknown"

	def _get_validate_info(self, data):
		return data["detected_vendors"]

	def _check_target_is_valid(self, target):
		assert isinstance(target, dict), "target is must be dict object"
		assert target["exist"], "this domain don't exist"
		assert target.has_key("detected_vendors"), "don't has must column detected_vendors"

	def _calc_risk(self, target):
		result = self._check_for_malicious(target)
		if result[0]:
			score  = _TYPE_.MALICIOUS
			reason = result[1]
			return score, self._get_reason(reason), result[2]
		result = self._check_for_suspicious(target)
		if result[0]:
			score  = _TYPE_.SUSPICIOUS
			reason = result[1]
			return score, self._get_reason(reason), result[2]
		else:
			score = _TYPE_.GOOD
			reason = _REASON_.GOOD
			return score, self._get_reason(reason), result[2]

	def _to_default_condition(self):
		self.set_condition_for_malicious(
				_KEY_.OR,
				detected_score= {
					_KEY_.VALIDATE_THRESHOLD: 20,
					_KEY_.MUST_VENDORS     : 20,
					_KEY_.RELIABLE_VENDORS : 7,
					_KEY_.NORMAL_VENDORS   : 3
				}
		)
		self.set_condition_for_suspicious(
				_KEY_.OR,
				detected_score= {
					_KEY_.VALIDATE_THRESHOLD: 15,
					_KEY_.MUST_VENDORS     : 20,
					_KEY_.RELIABLE_VENDORS : 7,
					_KEY_.NORMAL_VENDORS   : 3
				}
		)

	def _compare_detected_vendors(self, key, base, target):
		vendors = target
		score = 0
		threshold = base[_KEY_.VALIDATE_THRESHOLD]
		lv1_cost = base[_KEY_.MUST_VENDORS]
		lv2_cost = base[_KEY_.RELIABLE_VENDORS]
		lv3_cost = base[_KEY_.NORMAL_VENDORS]
		for each in vendors:
			each = each.lower()
			if each in self.lv1_vendors:
				score += lv1_cost
			elif each in self.lv2_vendors:
				score += lv2_cost
			else:
				score += lv3_cost
		if score >= threshold:
			return True, "Vendors({})".format(",".join(vendors))
		else:
			return False, ""

	def _and_compare(self, condition, target):
		chk_tgt = _KEY_.DETECTED_SCORE
		detected_points = []
		if condition.has_key(chk_tgt) and condition[chk_tgt]:
			flag, msg = self._compare_detected_vendors(chk_tgt, condition[chk_tgt], target)
			if flag:
				detected_points.append(msg)
			else:
				return (False, None, "")
		return (True, _REASON_.AND_ALL, ";".join(detected_points))

	def _or_compare(self, condition, target):
		chk_tgt = _KEY_.DETECTED_SCORE 
		if condition.has_key(chk_tgt) and condition[chk_tgt]:
			flag, msg = self._compare_detected_vendors(chk_tgt, condition[chk_tgt], target)
			if flag:
				return (True, _REASON_.DETECTED_SCORE, msg)
		return (False, None, "")

	def _check_for_suspicious(self, target):
		if not self.condition.has_key(_TYPE_.SUSPICIOUS):
			return (False, None, "")

		condition = self.condition[_TYPE_.SUSPICIOUS]
		if condition["base"] == "AND":
			return self._and_compare(condition, target)
		else:
			return self._or_compare(condition, target)

	def _check_for_malicious(self, target):
		if not self.condition.has_key(_TYPE_.MALICIOUS):
			return (False, None, "")

		condition = self.condition[_TYPE_.MALICIOUS]
		if condition["base"] == "AND":
			return self._and_compare(condition, target)
		else:
			return self._or_compare(condition, target)

	def _set_condition(self, base, result_type, **data):
		assert result_type==_TYPE_.SUSPICIOUS or result_type==_TYPE_.MALICIOUS, "result type is invalid"
		assert base in ("AND", "OR"), "base is invalid"
		assert isinstance(data, dict), "condition is acceptable with dict type"
		condition={}
		condition["base"]=base
		for each in _DEF_.HASH_CHECKs:
			if data.has_key(each):
				condition[each]=data[each]
			else:
				condition[each]=None
		self.condition[result_type]=condition

	def _get_reason(self, reason):
		msg = ""
		if reason is _REASON_.GOOD:
			msg = "this hash is benign"
		elif reason is _REASON_.AND_ALL:
			msg = "has multi malicious point"
		elif reason is _REASON_.DETECTED_SCORE:
			msg = "detected by many vendors"
		else:
			msg = ""
		return (reason, msg)
