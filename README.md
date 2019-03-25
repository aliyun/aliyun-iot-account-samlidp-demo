# SAML IDP DEMO
## 接口说明
1. /saml/metadata 用于IDP SAML 元数据的生成, 需要将该元数据提供给阿里云IOT用于身份接入
2. /saml/login    用于用户登陆
3. /saml/list     用于列出应用列表
4. /saml/sso      用于接受 SP AuthnRequest(SAML 请求)的URL,暂时没用

## 其他  

1. 生成X509证书命令的操作部署见`X509CertGenTest`类


