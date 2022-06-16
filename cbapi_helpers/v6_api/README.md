# v6バージョン:CarbonBlackAPI連携モジュール

## コマンドラインツール
### bin,logフォルダ

利用しない想定です。今後削除予定です。  
Note: ../binを利用予定  

## 設定ファイル
### configフォルダ

コマンドラインによるログ設定や各種API連携に伴うユーザごとの資格情報設定などが保管されています。  

## 本フォルダ直下の各スクリプト
### cb_api_helper.py

v6APIで連携する際に、importしてください。
以下が利用例となります。
```python
import cb_api_helper
api = cb_api_helper.init_by_cfg_file("dhsoc", "rest")
# NKYXE2OS というIDのアラートを取得
alert = api.get_alert_detail('NKYXE2OS') #return is dict
print alert
```

### cb_api_conf.py

APIに関する設定情報の取得用スクリプトです。
以下が利用例となります。
```python
import cb_api_conf
customers = cb_api_conf.get_customers() #return by list
cfg = cb_api_conf.get_conf("dhsoc")
print cfg
```
