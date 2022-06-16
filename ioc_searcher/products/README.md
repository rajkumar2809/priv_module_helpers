# IOC情報のハンティング対象製品毎でのクラス

DH-SOCのSplunkに保管しているIOC情報について、APIでハンティングをする際のクラスです。  

## 基本的なAPI連携用の各種モジュール  
### 本フォルダ直下のファイル

### base.py

IOC情報でのハンティングと結果をSplunkにPOSTする機能を定義しています。  
ただし、どちらも製品毎でindexや利用するAPI連携モジュールなどが異なるため、必要関数のみ定義されている状態です。(インタフェースのような状態)  

```python
def check_ioc(self, iocs):
def _post_to_splunk(self, _raw):
```

### cbdefense.py, crowdstrike.py, fireeye_hx.py

各製品向けのクラスです。  
base.pyが基底クラスとなります。
