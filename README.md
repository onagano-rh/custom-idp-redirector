# IdPの認可エンドポイントにリクエストパラメタを追加する方法

1. Browser flowのIdentity Provider RedirectorのConfigで使用するIdPのIDを設定

   これでログイン画面でIdPを選択することなく直接設定したIdPのログイン画面にリダイレクトされる。
   このサンプルコードでは `CustomIdpRedirector` にてリクエストパラメタを取得・保存している。

2. `CustomOIDCIdentityProvider` の `createAuthorizationUrl()` メソッド内で先に保存したパラメタを取得しIdP向けに再設定

