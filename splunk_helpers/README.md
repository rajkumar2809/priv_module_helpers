# splunk_helpers  

Splunk API操作用モジュールです。
実施する機能によっていくつかのモジュールを作成しています。  

## splunk_alert_searcher.py  

splunkでアラート検索をする用のモジュール。  
CarbonBlackでランサムウェアアラート用のrisk_checker/validatorで利用しています。  

## splunk_commands.py  

現在は利用していません。今後削除予定です。

## splunk_myioc_searcher.py  

splunkでdhsoc_threat_infoのIOC検索用モジュール。  
検索機能とともにデータをキャッシュして次回以降の検索をせずにローカルで処理できるようにしています。  

## splunk_post_helper.py  

SplunkにログをPOSTする用のモジュール。  
アラート内容をエンリッチした後やrisk_checkerでのチェック後の結果をPOSTする際に利用することを想定しています。  

## splunk_searcher.py  

splunkでログ検索をする際のモジュール。  
cyfirma IOCなどの検索に利用しています。  
