#!/bin/bash

echo "" > backup/lastcheck.txt

read -p "作業がどちらか選択して下さい(0 or 1 [0:add/1:del]):" ans

case "$ans" in [0] ) work=add ;; [1] ) work=del ;; *) echo "abort." ; exit ;; esac

echo "***devices.csvの差分チェック結果***" >> backup/lastcheck.txt
diff work/"$work"/config/cs_devices.csv backup/cs_devices.csv >> backup/lastcheck.txt

echo "***inputs.confの差分チェック結果***" >> backup/lastcheck.txt
diff work/"$work"/config/inputs.conf backup/inputs.conf >> backup/lastcheck.txt

echo "***oauth.json(共有api設定)の差分チェック結果***" >> backup/lastcheck.txt
diff work/"$work"/config/oauth.json backup/oauth.json >> backup/lastcheck.txt

echo "***threat_graph.json(共有api設定)の差分チェック結果***" >> backup/lastcheck.txt
diff work/"$work"/config/threat_graph.json backup/threat_graph.json >> backup/lastcheck.txt

echo "***CSAPI(credentials)(個別api設定)の差分チェック結果***" >> backup/lastcheck.txt
ls backup/credentials > backup/credentials_in_backup.txt
ls work/"$work"/config/credentials > backup/credentials_in_work.txt
diff backup/credentials_in_backup.txt backup/credentials_in_work.txt >> backup/lastcheck.txt

cat backup/lastcheck.txt

echo ""
if [[ $ans -eq 1 ]]; then
  read -p "削除内容に間違いがないですか? (y/N): " yn
else
  read -p "追加内容に間違いがないですか? (y/N): " yn
fi
case "$yn" in [yY]*) ;; *) echo "abort." ; exit ;; esac


if [[ $ans -eq 1 ]]; then
  echo "削除結果を送ります"
  curl -k https://$(hostname)/dhsoc/MasterMente/DeleteConfirmation.php?customer=$(cat work/del/target.txt | grep 顧客ID | cut -d ":" -f 2) -X POST -F file=@backup/lastcheck.txt -vv
fi
