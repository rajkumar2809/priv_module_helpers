# -*- coding: utf-8 -*-

import sys, os
import time, json, re, copy, glob, logging

reload(sys)
sys.setdefaultencoding("utf-8")

_CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
_CONF_DIR = _CURR_DIR+"/config"
_VENDOR_GEN_CONF = _CONF_DIR+"/vendor.json"
_VENDOR_RULE_DIR = _CONF_DIR+"/vtrule"

logger = logging.getLogger(__name__)

class VirusTotalConfidenceChecker(object):
	_SUS_FP_DIR_NAME = "sus_fp_rule"
	_PUP_DIR_NAME    = "pup_rule"

	@classmethod
	def _init_config(cls):
		with open(_VENDOR_GEN_CONF) as f:
			cls.gen_conf = json.load(f)
		cls.vendor = {}
		cls._parse_each_confidence("high")
		cls._parse_each_confidence("medium")
		cls._parse_each_confidence("low")

	@classmethod
	def check_confidence(cls, result):
		score = 0
		score += cls._check_score("high", result)
		logger.info("Score after Check HighVendor:{}".format(score))
		score += cls._check_score("medium", result)
		logger.info("Score after Check MediumVendor:{}".format(score))
		score += cls._check_score("low", result)
		logger.info("Score after Check LowVendor:{}".format(score))
		score += cls._check_score("others", result)
		logger.info("Score Total:{}".format(score))
		for each in cls.gen_conf["threthold"]:
			if score > each["score"]:
				return each["confidence"]
		return "false_positive"
	
	@classmethod
	def _check_score(cls, level, result):
		weight = cls.gen_conf["weight"][level]
		vector = cls.gen_conf["vector"]
		score = 0
		if level == "others":
			for vendor, desc in result.items():
				pt = "(?i)(hacktool|riskware|cracktool|cracker|unwanted.*program|\\.patcher\\.)"
				if( not(vendor in cls.vendor["high"]  ) and
					not(vendor in cls.vendor["medium"]) and
					not(vendor in cls.vendor["low"]) ):
					if re.search(pt, desc):
						score -= weight
					else:
						score += weight
			return score
		else:
			allrules = cls.vendor[level]
			for vendor, rules in allrules.items():
				if vendor in result:
					desc = result[vendor]
					flag = False
					for pt in rules[cls._SUS_FP_DIR_NAME]:
						if re.search(pt, desc):
							score += weight*vector["sus"]
							flag = True
							logger.debug("{} -> SUS_FP".format(vendor))
							break
					if flag:
						continue
					for pt in rules[cls._PUP_DIR_NAME]:
						if re.search(pt, desc):
							score += weight*vector["pup"]
							logger.debug("{} -> PUP".format(vendor))
							flag = True
							break
					if flag:
						continue
					logger.debug("{} -> MAL".format(vendor))
					score += weight*vector["mal"]
				else:
					logger.debug("{} -> GOOD".format(vendor))
					score += weight*vector["good"]
		return score

	@classmethod
	def _parse_each_confidence(cls, confidence):
		cls.vendor[confidence] = {}
		for each in cls.gen_conf["confidence"][confidence]:
			cls.vendor[confidence][each] = {
					cls._SUS_FP_DIR_NAME : [],
					cls._PUP_DIR_NAME : [] }
			for dirname in (cls._SUS_FP_DIR_NAME, cls._PUP_DIR_NAME):
				flist = _VENDOR_RULE_DIR+"/{}/{}/*.json".format(
						each, dirname)
				for fname in glob.glob(flist):
					try:
						with open(fname) as f:
							pt = json.load(f)["rule"]
						cls.vendor[confidence][each][dirname].append(pt)
					except Exception as e:
						pass



def __test__():
	alerts = {}
	for each in glob.glob(_CURR_DIR+"/testdata/vtcheck/*.json"):
		with open(each) as f:
			alerts[each] = json.load(f)
	
	for fname, result in alerts.items():
		logger.info("check file:{}".format(fname))
		confidence = VirusTotalConfidenceChecker.check_confidence(result)
		logger.info("confidence:{}".format(confidence))
	#print json.dumps(VirusTotalConfidenceChecker.vendor, indent=4)

if __name__ == '__main__':
	logging.basicConfig(
		level = logging.DEBUG,
		format = "%(asctime)s %(levelname)-s %(module)s:%(lineno)03d - %(message)s"
	)
	VirusTotalConfidenceChecker._init_config()
	__test__()
