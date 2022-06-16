# soc_operations  

各種SOC業務の関連ツールや自動化系のスクリプトを入れています。  

## analyst_comment_sync  

自動化系であり、splunk内での情報補完に利用しています。redmineでクローズしたチケットを確認し、splunkに反映させます。  
大きな利用用途として、低アラート一覧やブロック一覧に反映させることとなります。  

## auto_response  

Tier1 Appを自動処理するためのモジュール。  
現在は利用しておりません。(othersに本機能と類似したものが存在)  
いずれ切り出す予定であり、そのためにフォルダだけ存在しています。  

## cyfirma_sync  

脅威インテリジェンスサービス:decyfirからIOC情報を収集するためのモジュール。  

## make_analyst_report  

１次解析レポートを作成するためのモジュール。  
レポート作成自体は、別途report_helperが存在しているが、これを利用してCLIでレポート作成などをできるようにしています。

## manage_customer_config  

監視の開始における設定追加などを可能としているモジュール。  
現在は、carbonblackのみ対応。  

## others  

アナリスト向けのIVR呼び出し(call_ivr)や一次対応画面の自動実行(auto_response)を提供しているモジュール。  

## redmine_sync  

元々stellar監視で利用していましたが、現在は利用しておりません。
今後、削除予定です。  

## send_analyst_report  

元々stellar監視で利用していましたが、現在は利用しておりません。
今後、削除予定です。  

## triage_alert  

アラートの一次対応時におけるトリアージを提供するモジュール。  
一次対応画面でも呼び出されています。risk_checkerとの大きな違いはrisk_checkerの実行結果も踏まえたチェックを定義できることです。  
