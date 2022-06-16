#!/bin/bash

DAY1=$(date --date 'today' "+%Y-%m-%d")
DAY2=$(date --date '1 day ago' "+%Y-%m-%d")
DAY3=$(date --date '2 day ago' "+%Y-%m-%d")
CURRENT="/opt/python_private_modules/priv_module_helpers/risk_checker/cbdefense"
#CURRENT=$(cd $(dirname $0);pwd)

date > $CURRENT/log/deletecache.log

for each in $(ls $CURRENT/cache);
do
    if [[ $each = $DAY1 ]]; then
        echo "skip. this is today:"$each >> $CURRENT/log/deletecache.log;
    elif [[ $each = $DAY2 ]]; then
        echo "skip. this is 1 day ago:"$each >> $CURRENT/log/deletecache.log;
    elif [[ $each = $DAY3 ]]; then
        echo "skip. this is 2 day ago:"$each >> $CURRENT/log/deletecache.log;
    elif [[ ${each} =~ ^20[0-9]{2}-[01][0-9]-[0-3][0-9]$ ]]; then
        deldir=$CURRENT/cache/$each
        echo "deleted dir:"$deldir >> $CURRENT/log/deletecache.log;
        rm -f -r $deldir
        echo "afterfilenum:"$(ls $deldir | wc -l) >> $CURRENT/log/deletecache.log;
    else
        echo "skip. unknown format:"$each >> $CURRENT/log/deletecache.log;
    fi
done
