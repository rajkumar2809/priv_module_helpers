class VtValidatorConst():
	pass

class EachSection():
	pass

BASE = VtValidatorConst
BASE.Level=EachSection()
BASE.Result=EachSection()
BASE.Reason=EachSection()
BASE.KEY=EachSection()
BASE.Default=EachSection()

BASE.Level.AGRESSIVE = 3
BASE.Level.MEDIUM = 2
BASE.Level.CERTAINTY = 1
BASE.Result.MALICIOUS = 5
BASE.Result.SUSPICIOUS = 2
BASE.Result.GOOD = 0
BASE.Reason.GOOD = 0
BASE.Reason.AND_ALL = 99
BASE.Reason.TOTAL_DETECT_URL_NUM = 1
BASE.Reason.TOTAL_OVER_URL_NUM = 2
BASE.Reason.HAS_MAL_CATEGORIES = 3
BASE.Reason.UNKNOWN_NEW_HOST = 4
BASE.Reason.DETECTED_SCORE = 1

BASE.KEY.AND = "AND"
BASE.KEY.OR = "OR"
BASE.KEY.Lv1 = "lv1"
BASE.KEY.Lv2 = "lv2"
BASE.KEY.VALIDATE_THRESHOLD = "threshold"
BASE.KEY.VALIDATE_URLNUM = "num"
BASE.KEY.TOTAL_DETECT_URL_NUM = "total_detect_url"
BASE.KEY.TOTAL_OVER_URL_NUM = "threshold_over_url_num"
BASE.KEY.HAS_MAL_CATEGORIES = "has_malicious_categories"
BASE.KEY.UNKNOWN_NEW_HOST = "unknown_with_nearly_creation_date"
BASE.KEY.DETECTED_SCORE = "detected_score"
BASE.KEY.MUST_VENDORS = "must_vendors"
BASE.KEY.RELIABLE_VENDORS = "reliable_vendors"
BASE.KEY.NORMAL_VENDORS = "normal_vendors"

BASE.Default.DOMAIN_CHECKs=(
		BASE.KEY.TOTAL_DETECT_URL_NUM,
		BASE.KEY.TOTAL_OVER_URL_NUM,
		BASE.KEY.HAS_MAL_CATEGORIES,
		BASE.KEY.UNKNOWN_NEW_HOST
)

BASE.Default.IP_CHECKs=(
		BASE.KEY.TOTAL_DETECT_URL_NUM,
		BASE.KEY.TOTAL_OVER_URL_NUM,
)

BASE.Default.HASH_CHECKs = (
	BASE.KEY.DETECTED_SCORE,
)

BASE.Default.MAL_CATEGORY_KEYWORDS = (
		"phishing",
		"malicious",
		"malware",
		"suspicious",
		"infect",
		"not recommended"
)

BASE.Default.LV1_VENDORS_KEYWORD = (
	"mcafee",
	"trendmicro",
	"symantec",
	"microsoft"
)

BASE.Default.LV2_VENDORS_KEYWORD = (
	"sophos",
	"kaspersky",
	"fortinet",
	"f-secure",
	"crowdstrike",
	"cybereason",
	"cylance",
	"malwarebytes",
	"paloalto"
)

