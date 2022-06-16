import sys, os
import re, json
from time import mktime
from datetime import datetime
from validate_const import VtValidatorConst as const_v

# AGRESSIVE > MEDIUM > CERTAINTY

_KEY_=const_v.KEY
_TYPE_=const_v.Result
_DEF_=const_v.Default

class DomainValidator(object):
	def __init__(self, use_default=True):
		self.condition = {}
		self.init_malicious_categories()
		if use_default:
			self._to_default_condition()

	def init_malicious_categories(self, keywords=None):
		if keywords:
			assert hasattr(keywords, "__iter__"), "keywords must be iterable type"
			self.mal_categories = []
			for each in keywords:
				self.add_mal_category(each)
		else:
			self.mal_categories = list(_DEF_.MAL_CATEGORY_KEYWORDS)

	def add_mal_category(self, keyword):
		assert( isinstance(keyword, str) or isinstance(keyword, unicode)
				), "each word must be type of str or unicode"
		self.mal_categories.append(keyword)

	def validate(self, target):
		self._check_target_is_valid(target)
		info = self._get_validate_info(target)
		score, reason, detected_point = self._calc_risk(info)
		return {
				"value"       : target["name"],
				"score"       : score,
				"reputation"  : self._get_reputation(score),
				"reason_code" : reason[0],
				"reason"      : reason[1],
				"detected_point" : detected_point }
	
	def days_from_created(self, data):
		create_date = data["create_date"]
		if create_date and len(create_date) is not 0:
			tmp = create_date.split("-")
			create_date = datetime(int(tmp[0]),int(tmp[1]),int(tmp[2]), 0, 0, 0)
			now = datetime.now()
			diff = int(mktime(now.timetuple()))-int(mktime(create_date.timetuple()))
			return diff / 86400
		else:
			return None

	def clear_condition(self, result_type=None):
		if result_type is None:
			self.condition.clear()
		elif result_type == _TYPE_.MALICIOUS:
			if self.condition.has_key(_TYPE_.MALICIOUS):
				del(self.condition[_TYPE_.MALICIOUS])
		elif result_type == _TYPE_.SUSPICIOUS:
			if self.condition.has_key(_TYPE_.SUSPICIOUS):
				del(self.condition[_TYPE_.SUSPICIOUS])

	def get_condition(self):
		return self.condition

	def set_condition_for_suspicious(self, base, **data):
		"""
		[str] base (AND | OR)
		expected_key at data
			[int]  total_detect_url
			[list] threshold_over_url_num
				([int]threshold_over_url_num, [int]url_num)
			[bool] has_malicious_categories
			[int]  unknown_with_nearly_creation_date
		-> None
		"""
		self._set_condition(base, _TYPE_.SUSPICIOUS, **data)

	def set_condition_for_malicious(self, base, **data):
		"""
		[str] base (AND | OR)
		expected_key at data
			[int]  total_detect_url
			[list] threshold_over_url_num
				([int]threshold_over_url_num, [int]url_num)
			[bool] has_malicious_categories
			[int]  unknown_with_nearly_creation_date
		-> None
		"""
		self._set_condition(base, _TYPE_.MALICIOUS, **data)

	##### followings are private #####

	def _get_reputation(self, score):
		if score is _TYPE_.MALICIOUS:
			return "malicious"
		elif score is _TYPE_.SUSPICIOUS:
			return "suspicious"
		elif score is _TYPE_.GOOD:
			return "benign"
		else:
			return "unknown"

	def _calc_risk(self, target):
		assert len(self.condition) is not 0, "no set any conditions"
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
			reason = const_v.Reason.GOOD
			return score, self._get_reason(reason), result[2]

	def _check_target_is_valid(self, target):
		assert isinstance(target, dict), "target is must be dict object"
		assert target["exist"], "this domain don't exist"
		assert target.has_key("create_date"), "don't has must column create_date"
		assert target.has_key("detected_urls"), "don't has must column detected_urls"
		assert target.has_key("categories"), "don't has must column categories"

	def _get_validate_info(self, data):
		result = {}
		detected_urls = data["detected_urls"]
		result[_KEY_.TOTAL_DETECT_URL_NUM]=len(detected_urls)
		summary = {}
		for each in detected_urls:
			each_positives = each["positives"]
			if not summary.has_key(each_positives):
				summary[each_positives] = 0
			summary[each_positives] += 1
		result[_KEY_.TOTAL_OVER_URL_NUM]=summary
		result[_KEY_.HAS_MAL_CATEGORIES]=data["categories"]
		result[_KEY_.UNKNOWN_NEW_HOST]=(data["exist"], self.days_from_created(data))
		return result

	def _to_default_condition(self):
		self.set_condition_for_malicious(
				_KEY_.OR,
				has_malicious_categories=True,
				unknown_with_nearly_creation_date=7
		)
		self.set_condition_for_suspicious(
				_KEY_.OR,
				total_detect_url=100,
				threshold_over_url_num= (4, 5),
				has_malicious_categories=True,
				unknown_with_nearly_creation_date=30
		)

	def _compare_total_detect_url(self, key, base, target):
		if target.has_key(key):
			target_value = target[key]
			if target_value >= base:
				return True, "DetectedManyURL({})".format(target_value)
			else:
				return False, ""
		else:
			return False, ""

	def _compare_threshold_over_urls(self, key, base, target):
		threshold = base[0]
		condition = base[1]
		target_value = 0
		if target.has_key(key):
			for positives, num in target[key].items():
				if positives >= threshold:
					target_value += num
			if target_value > condition:
				return True, "DetectedManyVendors(URLNum={},VendorNum={})".format(target_value, threshold)
			else:
				return False, ""
		else:
			return False, ""

	def _compare_has_mal_categories(self, key, base, target):
		categories = target[key]
		for each in self.mal_categories:
			for each_category in categories:
				if each in each_category:
					return True, "MalCategory({})".format(each_category)
		return False, ""

	def _compare_unknown_new_host(self, key, base, target):
		info = target[key]
		if info[0]:
			if info[1] is None or info[1] < base:
				return True, "NoReputationYoung(PastDays:{})".format(info[1])
			else:
				return False, ""
		else:
			return False, ""

	def _and_compare(self, condition, target):
		chk_tgt = _KEY_.TOTAL_DETECT_URL_NUM
		detected_points = []
		if condition.has_key(chk_tgt) and condition[chk_tgt]:
			flag, msg = self._compare_total_detect_url(chk_tgt, condition[chk_tgt], target)
			if flag:
				detected_points.append(msg)
			else:
				return (False, None, "")

		chk_tgt = _KEY_.TOTAL_OVER_URL_NUM
		if condition.has_key(chk_tgt) and condition[chk_tgt]:
			flag, msg = self._compare_threshold_over_urls(chk_tgt, condition[chk_tgt], target)
			if flag:
				detected_points.append(msg)
			else:
				return (False, None, "")

		chk_tgt = _KEY_.HAS_MAL_CATEGORIES
		if condition.has_key(chk_tgt) and condition[chk_tgt]:
			flag, msg = self._compare_has_mal_categories(chk_tgt, condition[chk_tgt], target)
			if flag:
				detected_points.append(msg)
			else:
				return (False, None, "")

		chk_tgt = _KEY_.UNKNOWN_NEW_HOST
		if condition.has_key(chk_tgt) and condition[chk_tgt]:
			flag, msg = self._compare_unknown_new_host(chk_tgt, condition[chk_tgt], target)
			if flag:
				detected_points.append(msg)
			else:
				return (False, None, "")
		return (True, const_v.Reason.AND_ALL, ";".join(detected_points))

	def _or_compare(self, condition, target):
		chk_tgt = _KEY_.HAS_MAL_CATEGORIES
		if condition.has_key(chk_tgt) and condition[chk_tgt]:
			flag, msg = self._compare_has_mal_categories(chk_tgt, condition[chk_tgt], target)
			if flag:
				return (True, const_v.Reason.HAS_MAL_CATEGORIES, msg)

		chk_tgt = _KEY_.TOTAL_DETECT_URL_NUM
		if condition.has_key(chk_tgt) and condition[chk_tgt]:
			flag, msg = self._compare_total_detect_url(chk_tgt, condition[chk_tgt], target)
			if flag:
				return (True, const_v.Reason.TOTAL_DETECT_URL_NUM, msg)

		chk_tgt = _KEY_.TOTAL_OVER_URL_NUM
		if condition.has_key(chk_tgt) and condition[chk_tgt]:
			flag, msg = self._compare_threshold_over_urls(chk_tgt, condition[chk_tgt], target)
			if flag:
				return (True, const_v.Reason.TOTAL_OVER_URL_NUM, msg)

		chk_tgt = _KEY_.UNKNOWN_NEW_HOST
		if condition.has_key(chk_tgt) and condition[chk_tgt]:
			flag, msg = self._compare_unknown_new_host(chk_tgt, condition[chk_tgt], target)
			if flag:
				return (True, const_v.Reason.UNKNOWN_NEW_HOST, msg)
		return (False, None, "")

	def _check_for_suspicious(self, target):
		if not self.condition.has_key(_TYPE_.SUSPICIOUS):
			return (False, None, "")

		condition = self.condition[_TYPE_.SUSPICIOUS]
		if condition["base"] == _KEY_.AND:
			return self._and_compare(condition, target)
		else:
			return self._or_compare(condition, target)

	def _check_for_malicious(self, target):
		if not self.condition.has_key(_TYPE_.MALICIOUS):
			return (False, None, "")

		condition = self.condition[_TYPE_.MALICIOUS]
		if condition["base"] == _KEY_.AND:
			return self._and_compare(condition, target)
		else:
			return self._or_compare(condition, target)

	def _set_condition(self, base, result_type, **data):
		assert( result_type==_TYPE_.SUSPICIOUS or result_type==_TYPE_.MALICIOUS
				), "result type is invalid"
		assert( base in (_KEY_.AND, _KEY_.OR)
				), "1st arg is only accept AND or OR."
		condition={}
		condition["base"]=base
		for each in _DEF_.DOMAIN_CHECKs:
			if data.has_key(each):
				condition[each]=data[each]
			else:
				condition[each]=None
		self.condition[result_type]=condition

	def _get_reason(self, reason):
		msg = ""
		if reason is None:
			msg = ""
		elif reason is const_v.Reason.AND_ALL:
			msg = "has multi malicious point"
		elif reason is const_v.Reason.TOTAL_DETECT_URL_NUM:
			msg = "has many malicious URL"
		elif reason is const_v.Reason.TOTAL_OVER_URL_NUM:
			msg = "detected as malicious by many vendors."
		elif reason is const_v.Reason.HAS_MAL_CATEGORIES:
			msg = "malicious category"
		elif reason is const_v.Reason.UNKNOWN_NEW_HOST:
			msg = "this domain has no reputation, and created at recently(or no created date info)."
		elif reason is const_v.Reason.GOOD:
			msg = "this domain is benign."
		else:
			msg = ""
		return (reason, msg)

