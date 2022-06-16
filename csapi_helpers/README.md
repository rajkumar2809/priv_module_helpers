# CrowdStrike API連携モジュール

EDR製品:CrowdStrike のAPI連携用モジュールです。  
CrowdStrike のAPIは、バージョン変更が発生しているため、それぞれ以下を利用する必要があります。  

## 基本的なAPI連携用の各種モジュール  

本フォルダ直下に存在する各スクリプトになります。  

### cs_api_helper.py

crowdstrikeのAPI連携利用時に基本的に利用するモジュールです。  
以下が利用例となります。
```python
import cs_api_helper
api = cs_api_helper.CSApiHelper("DGH1")
# ldt:7882ab5814d7421ba7e3f4db46d86e37:103079738842 というIDのアラートを取得
alert = api.get_alert('ldt:7882ab5814d7421ba7e3f4db46d86e37:103079738842') #return is dict
print alert
```

### oauth_api_base.py

内部利用想定であり、外部からimportされることを想定していません。  
cs_api_helperからの利用想定となります。機能は、oauthのトークン処理などを提供するための基本機能とデコレータなどの提供です。

### cfg_mgr.py

内部利用想定であり、外部からimportされることを想定していません。  
cs_api_helperからの利用想定となります。機能は、各種設定情報をまとめて読み込む機能を提供しています。

## コマンドラインツール
### bin,logフォルダ

バージョンに限らず、コマンドベースでAPI連携する場合は、binフォルダ配下の各種スクリプトを実行します。  
また、実行に伴うログ情報がlogフォルダ内に保存されます。

## 設定ファイル
### configフォルダ

コマンドラインによるログ設定や各種API連携に伴うユーザごとの資格情報設定などが保管されています。  

## oauthトークンファイル
### tokenフォルダ

CrowdStrikeではAPIは基本的にoauthを利用しています。  
このフォルダはoauthで割り出されたtoken情報を保管するためのフォルダです。
