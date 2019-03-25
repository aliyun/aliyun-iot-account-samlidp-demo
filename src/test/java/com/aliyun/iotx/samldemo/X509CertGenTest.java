package com.aliyun.iotx.samldemo;

import com.aliyun.iotx.samldemo.util.SamlKeyStoreProvider;

/**
 *
 * 1.生成RSA私钥
 * 加密形式:
 * openssl genrsa -aes128 -passout pass:111111 -out rsa_aes_private.key 2048
 *
 * 类似下面的输出
 *
 * Generating RSA private key, 2048 bit long modulus
 * ..+++
 * ...........................................................................................................................................................................+++
 * e is 65537 (0x10001)
 *
 * 生成的 rsa_private.key 是未加密的RSA密钥
 *
 * 生成RSA对应的公钥
 * openssl rsa -in rsa_aes_private.key -passin pass:111111 -pubout -out rsa_public.key
 * 这个只是公钥, SAML 用途场景下不需要生成
 *
 *
 * 2. 生成证书请求文件, 可以使用 -days ${天数} 生成较长时间的证书
 * openssl req -new -key rsa_aes_private.key -passin pass:111111 -out client.pem
 *
 * 3. 生成X509证书,将原来证书文件覆盖,如果要保存可以将下面命令生成的 client.pem 名称修改
 *
 *  openssl req -x509 -key rsa_aes_private.key -in client.pem -out client.pem
 *
 * 4.最后生成的2个文件
 * rsa_aes_private.key 是私钥
 * client.pem 是证书
 *
 *
 * PS:
 * 使用
 * openssl genrsa -out rsa_private.key 2048
 * 可以生成不加密的私钥,然后执行
 * openssl rsa -in rsa_private.key -aes256 -passout pass:111111 -out rsa_aes_private.key
 * 对刚才的私钥进行加密
 *
 * @see SamlKeyStoreProvider 中使用 pass 中的参数读取私钥与证书
 *
 * @date 2019/2/17
 */
public class X509CertGenTest {


}
