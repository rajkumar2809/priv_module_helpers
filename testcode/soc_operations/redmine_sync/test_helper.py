#TODO dont use unittest yet.

from priv_module_helpers.soc_operations.redmine_sync import helper
import os, sys
_dir = os.getcwd()
_file = _dir+"/testdata/cbdefensealerts9.csv.gz"
from logging import basicConfig, DEBUG
basicConfig(level=DEBUG)
res = helper.boot_rmsync("cbdefense", _file, by_local=False)

