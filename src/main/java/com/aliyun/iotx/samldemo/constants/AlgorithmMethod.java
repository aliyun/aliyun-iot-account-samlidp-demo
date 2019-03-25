package com.aliyun.iotx.samldemo.constants;

public enum AlgorithmMethod {
	RSA_SHA1("http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
	RSA_SHA256("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
	RSA_SHA512("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"),
	RSA_RIPEMD160("http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160");

	private final String urn;

	AlgorithmMethod(String urn) {
		this.urn = urn;
	}

	public static AlgorithmMethod fromUrn(String urn) {
		for (AlgorithmMethod m : values()) {
			if (m.urn.equalsIgnoreCase(urn)) {
				return m;
			}
		}
		return null;
	}

	@Override
	public String toString() {
		return urn;
	}
}