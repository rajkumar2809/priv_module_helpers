# CarbonBlackAPI連携モジュール

EDR製品:CarbonBlackのAPI連携用モジュールです。  
CarbonBlackのAPIは、バージョン変更が発生しているため、それぞれ以下を利用する必要があります。  

## 基本的なAPI連携用の各種モジュール  
### 直下及びv6_apiフォルダ

- v3 : 2021/8まで利用可能  
  本モジュール直下を利用する場合、v3利用となります。(今後削除予定)
- v6 : 2021/8以降の標準  
  v6APIは今後利用されるAPIバージョンとなります。2021/8以降は本機能が標準です。

## コマンドラインツール
### bin,logフォルダ

バージョンに限らず、コマンドベースでAPI連携する場合は、binフォルダ配下の各種スクリプトを実行します。  
また、実行に伴うログ情報がlogフォルダ内に保存されます。

## 設定ファイル
### configフォルダ

コマンドラインによるログ設定や各種API連携に伴うユーザごとの資格情報設定などが保管されています。  

## 本フォルダ直下の各スクリプト
### cb_api_helper.py

利用しない想定です。今後削除予定です。
v3APIで連携する際に、importしてください。
以下が利用例となります。
```python
import cb_api_helper
api = cb_api_helper.init_by_cfg_file("dhsoc", "rest")
# NKYXE2OS というIDのアラートを取得
alert = api.get_alert_detail('NKYXE2OS') #return is dict
print alert
```

### cb_api_conf.py

利用しない想定です。今後削除予定です。
APIに関する設定情報の取得用スクリプトです。
以下が利用例となります。
```python
import cb_api_conf
customers = cb_api_conf.get_customers() #return by list
cfg = cb_api_conf.get_conf("dhsoc")
print cfg
```

### commands.py

利用しない想定です。今後削除予定です。
