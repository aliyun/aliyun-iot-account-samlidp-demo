package com.aliyun.iotx.samldemo.util;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;
import static org.springframework.util.StringUtils.hasText;

/**
 * 用于解析证书与私钥的工具类
 */
public class SamlKeyStoreProvider {
	/**
	 * 名字可以随意,作为证书的别名
	 */
	private  static String name = "certificate";

	private static char[] DEFAULT_KS_PASSWD = UUID.randomUUID().toString().toCharArray();

	private  static KeyStore getKeyStore(String privateKeyString, String certificateString, String password) {
		try {
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(null, DEFAULT_KS_PASSWD);

			byte[] certbytes = X509Utilities.getDER(certificateString);
			Certificate certificate = X509Utilities.getCertificate(certbytes);
			ks.setCertificateEntry(name, certificate);

			if (hasText(privateKeyString)) {
				PrivateKey pkey = X509Utilities.readPrivateKey(privateKeyString, password);
				ks.setKeyEntry(name, pkey, password.toCharArray(), new Certificate[]{certificate});
			}

			return ks;
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private static KeyStoreCredentialResolver getCredentialsResolver(String key, String cer, String password) {
		KeyStore ks = getKeyStore(key, cer, password);
		Map<String, String> passwords = hasText(key) ?
			Collections.singletonMap(name, password) :
			Collections.emptyMap();
		KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(
			ks,
			passwords
		);
		return resolver;
	}
	public static Credential getCredential(String key, String cer, String password) {
		try {
			KeyStoreCredentialResolver resolver = getCredentialsResolver(key, cer, password);
			CriteriaSet cs = new CriteriaSet();
			EntityIdCriterion criteria = new EntityIdCriterion(name);
			cs.add(criteria);
			return resolver.resolveSingle(cs);
		} catch (ResolverException e) {
			throw new RuntimeException("Can't obtain SP private key", e);
		}
	}

}