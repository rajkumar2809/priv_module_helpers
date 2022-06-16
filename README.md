# priv_module_helpers

本ツールには、各モジュールを楽に使えるようにしています。  
他と違い、独立性はありません。  
また、設定ファイルなどを保持させています。  

本プロジェクトに含まれる各種機能を以下に示します。

## cbapi_helpers, csapi_helpers, hxapi_helpers

各EDR製品のAPIに関する処理をするものです。  
メッセージ送信や隔離、アラートデータの取得など、全体的な操作を想定しています。  
- cbapi_helpers : CarbonBlack
- csapi_helpers : CrowdStrike
- hxapi_helpers : FireeyeHx

## helix_helpers

FireEyeのSIEM製品であるhelixとのAPI連携用モジュールです。  
イベントの取得処理をするためのものです。  

## redmine_helpers

プロジェクト管理ツール:redmineとの連携用モジュールです。  
チケットの作成・更新などの処理をするものであり、DH-SOC内での各種製品向けに操作を想定しています。  

## splunk_helpers

データ検索ツール:Splunkとの連携用モジュールです。  
SplunkへのデータPOSTやSplunkのデータ検索をすることを想定しています。

## cyfirma_helpers, sophos_central_helpers, sophos_xdr_api_helpers, trans_helpers, vtapi_helpers

それぞれ、各種製品やクラウドサービスへのAPI連携用モジュールです。
- cyfirma_helpers : 脅威情報サービス:cyfirma
- sophos_central_helpers,sophos_xdr_api_helpers : セキュリティツール:sophosクラウドサービス
- trans_helpers : Google翻訳
- vtapi_helpers : virustotal

## soc_operations

SOC業務系の自動化用モジュールです。  
レポートの作成、alertのtriage、アナリストのコメント情報の収集、自動応答やIVR連携などの機能があります。  
また、ユーザ向け設定をするためのCLI機能など構築・設定関連の機能があります。

## upload2mickyapp

判定結果の情報をMickyApp（一次対応画面などのUIツール）へ連携するモジュールです。  
ブロック一覧、低アラート一覧への連携が目的です。

## report_helpers

1次レポートや月次レポートの作成機能モジュールです。  
月次レポートは手動でレポート作成することを想定しています。

## ioc_searcher

cyfirmaや内部のIOC情報などを包括してチェックするモジュールです。  

## risk_checker

各種製品の過検知判定ツールです。  
主に各種EDR(cbdefense, crowdstrike, fireeyehx)を想定しています。

## その他
testcodeフォルダは、これらのモジュールのunittestコードを保存しています。  
そのため、利用されることを想定しているものではありません。


EoF
