# IOC情報ソース毎でのクラス

DH-SOCのSplunkに保管しているIOC情報について、ソース毎でのデータ取得・検索・parse用のクラスです。  
DH-SOCはIOC情報のソースとして、以下があるのでそれぞれに対する操作となります。  
- cyfirma
- 独自

基本的に同じ呼び出しを必須としますが、現状は基底クラスやインタフェースは定義できていません。

## 基本的なAPI連携用の各種モジュール  
### 本フォルダ直下のファイル

### cyfirma_searcher.py

cyfirmaのIOC情報を検索するためのクラスです。  
cyfirmaのIOCは、以下Splunkで定期的に取得して保管しているため、このSplunkへのアクセスを行なってチェックしています。

- Splunk名: splunk-license01.dhsoc.jp

基本的には以下メソッドを利用します。

```python
class Checker(object):
	def get_iocs(self, date_range=_YESTERDAY, ioc_num=5000):
    # ... 期間を指定してIOC情報を取得
  def check_ipv4(self, addresses):
    # ... IPでの検索
	def check_domains(self, domains):
    # ... ドメインでの検索
	def check_hashes(self, hashes):
    # ... sha256ハッシュでの検索
```

### dhsoc_searcher.py

独自のIOC情報を検索するためのクラスです。
IOCを追加したい場合は、csvファイル(dosoc_ioc.csv)でインポートする形です。
基本的な利用方法は、以下と同様です。
- cyfirma_searcher.py
