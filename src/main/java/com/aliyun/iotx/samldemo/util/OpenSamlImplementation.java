/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package com.aliyun.iotx.samldemo.util;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.Clock;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.annotation.PostConstruct;
import javax.xml.datatype.Duration;
import javax.xml.namespace.QName;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import com.aliyun.iotx.samldemo.constants.AlgorithmMethod;
import com.aliyun.iotx.samldemo.constants.CanonicalizationMethod;
import com.aliyun.iotx.samldemo.constants.DigestMethod;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.DOMTypeSupport;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSBase64Binary;
import org.opensaml.core.xml.schema.XSBoolean;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.XSURI;
import org.opensaml.core.xml.schema.impl.XSAnyBuilder;
import org.opensaml.core.xml.schema.impl.XSBooleanBuilder;
import org.opensaml.core.xml.schema.impl.XSDateTimeBuilder;
import org.opensaml.core.xml.schema.impl.XSIntegerBuilder;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.core.xml.schema.impl.XSURIBuilder;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.config.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.support.ChainingEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.opensaml.xmlsec.signature.support.Signer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Objects.isNull;
import static java.util.Optional.ofNullable;

/**
 * opensaml v3 的实现类
 */
@Component
public class OpenSamlImplementation {
	/**
	 * openssl 生成 私钥时所使用的密码
	 */
	@Value("${iot.key.password}")
	private String password;

	private static final Log logger = LogFactory.getLog(OpenSamlImplementation.class);
	private final AtomicBoolean hasInitCompleted = new AtomicBoolean(false);
	private Clock time;
	private BasicParserPool parserPool;
	private ChainingEncryptedKeyResolver encryptedKeyResolver;
	private static RandomIdentifierGenerationStrategy secureRandomIdGenerator;
	static {
		secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();
	}
    @PostConstruct
    public void springInit(){
	    init();
    }

	public OpenSamlImplementation(){
	    this(Clock.systemUTC());
    }

	public OpenSamlImplementation(Clock time) {
		this.time = time;
		this.parserPool = new BasicParserPool();
	}

    public String transformSAMLObject2String(SAMLObject samlObject) throws MarshallingException {
        return SerializeSupport.nodeToString(getMarshallerFactory()
            .getMarshaller(samlObject)
            .marshall(samlObject));
    }

    private OpenSamlImplementation init() {
        if (!hasInitCompleted.get()) {
            performInit();
        }
        return this;
    }

    private synchronized void performInit() {
        if (hasInitCompleted.compareAndSet(false, true)) {
            java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider()
            );
            bootstrap();
        }
    }

   

    private BasicParserPool getParserPool() {
		return parserPool;
	}

	public MarshallerFactory getMarshallerFactory() {
		return XMLObjectProviderRegistrySupport.getMarshallerFactory();
	}

	public UnmarshallerFactory getUnmarshallerFactory() {
		return XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
	}

	public Credential getSelfCredential(){
		return IDPCredentials.getCredential(this.password);
	}

	public void signObject(SignableSAMLObject signable,
						   AlgorithmMethod algorithm,
						   DigestMethod digest) {



		XMLObjectBuilder<Signature> signatureBuilder =
			(XMLObjectBuilder<org.opensaml.xmlsec.signature.Signature>) getBuilderFactory()
				.getBuilder(org.opensaml.xmlsec.signature.Signature.DEFAULT_ELEMENT_NAME);
		org.opensaml.xmlsec.signature.Signature signature = signatureBuilder.buildObject(org.opensaml.xmlsec
			.signature.Signature.DEFAULT_ELEMENT_NAME);

		signable.setSignature(signature);

		SignatureSigningParameters parameters = new SignatureSigningParameters();
		parameters.setSigningCredential(IDPCredentials.getCredential(password));
		parameters.setKeyInfoGenerator(getKeyInfoGenerator(IDPCredentials.getCredential(password)));
		parameters.setSignatureAlgorithm(algorithm.toString());
		parameters.setSignatureReferenceDigestMethod(digest.toString());
		parameters.setSignatureCanonicalizationAlgorithm(
			CanonicalizationMethod.ALGO_ID_C14N_EXCL_OMIT_COMMENTS.toString()
		);

		try {
			SignatureSupport.prepareSignatureParams(signature, parameters);
			Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(signable);
			marshaller.marshall(signable);
			Signer.signObject(signature);
		} catch (SecurityException | MarshallingException | SignatureException e) {
			throw new RuntimeException(e);
		}
	}
	public KeyInfoGenerator getKeyInfoGenerator(Credential credential) {
		NamedKeyInfoGeneratorManager manager = DefaultSecurityConfigurationBootstrap
			.buildBasicKeyInfoGeneratorManager();
		return manager.getDefaultManager().getFactory(credential).newInstance();
	}


	public XMLObjectBuilderFactory getBuilderFactory() {
		return XMLObjectProviderRegistrySupport.getBuilderFactory();
	}

	protected void bootstrap() {
		//configure default values
		//maxPoolSize = 5;
		parserPool.setMaxPoolSize(50);
		//coalescing = true;
		parserPool.setCoalescing(true);
		//expandEntityReferences = false;
		parserPool.setExpandEntityReferences(false);
		//ignoreComments = true;
		parserPool.setIgnoreComments(true);
		//ignoreElementContentWhitespace = true;
		parserPool.setIgnoreElementContentWhitespace(true);
		//namespaceAware = true;
		parserPool.setNamespaceAware(true);
		//schema = null;
		parserPool.setSchema(null);
		//dtdValidating = false;
		parserPool.setDTDValidating(false);
		//xincludeAware = false;
		parserPool.setXincludeAware(false);

		Map<String, Object> builderAttributes = new HashMap<>();
		parserPool.setBuilderAttributes(builderAttributes);

		Map<String, Boolean> parserBuilderFeatures = new HashMap<>();
		parserBuilderFeatures.put("http://apache.org/xml/features/disallow-doctype-decl", TRUE);
		parserBuilderFeatures.put("http://javax.xml.XMLConstants/feature/secure-processing", TRUE);
		parserBuilderFeatures.put("http://xml.org/sax/features/external-general-entities", FALSE);
		parserBuilderFeatures.put(
			"http://apache.org/xml/features/validation/schema/normalized-value",
			FALSE
		);
		parserBuilderFeatures.put("http://xml.org/sax/features/external-parameter-entities", FALSE);
		parserBuilderFeatures.put("http://apache.org/xml/features/dom/defer-node-expansion", FALSE);
		parserPool.setBuilderFeatures(parserBuilderFeatures);

		try {
			parserPool.initialize();
		} catch (ComponentInitializationException x) {
			throw new RuntimeException("Unable to initialize OpenSaml v3 ParserPool", x);
		}


		try {
			InitializationService.initialize();
		} catch (InitializationException e) {
			throw new RuntimeException("Unable to initialize OpenSaml v3", e);
		}

		XMLObjectProviderRegistry registry;
		synchronized (ConfigurationService.class) {
			registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
			if (registry == null) {
				registry = new XMLObjectProviderRegistry();
				ConfigurationService.register(XMLObjectProviderRegistry.class, registry);
			}
		}

		registry.setParserPool(parserPool);
		encryptedKeyResolver = new ChainingEncryptedKeyResolver(
			asList(
				new InlineEncryptedKeyResolver(),
				new EncryptedElementTypeEncryptedKeyResolver(),
				new SimpleRetrievalMethodEncryptedKeyResolver()
			)
		);
	}


	public static String generateSecureRandomId() {
		return secureRandomIdGenerator.generateIdentifier();
	}

	protected XMLObject parse(byte[] xml) {
		try {
			Document document = getParserPool().parse(new ByteArrayInputStream(xml));
			Element element = document.getDocumentElement();
			return getUnmarshallerFactory().getUnmarshaller(element).unmarshall(element);
		} catch (UnmarshallingException | XMLParserException e) {
			throw new RuntimeException(e);
		}
	}

	public XMLObject transferXML2SAMLObject(String str){
		return parse(str.getBytes());
	}

	public <T> T buildSAMLObject(final Class<T> clazz) {
		T object = null;
		try {
			QName defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
			object = (T) getBuilderFactory().getBuilder(defaultElementName).buildObject(defaultElementName);
		} catch (IllegalAccessException e) {
			throw new RuntimeException("Could not create SAML object", e);
		} catch (NoSuchFieldException e) {
			throw new RuntimeException("Could not create SAML object", e);
		}

		return object;
	}


	public String encode(byte[] b) {
		return EncodingUtils.encode(b);
	}

	public byte[] decode(String s) {
		return EncodingUtils.decode(s);
	}

	public byte[] deflate(String s) {
		return EncodingUtils.deflate(s);
	}

	public String inflate(byte[] b) {
		return EncodingUtils.inflate(b);
	}
	/**
	 * 可以用于打印 SAML object
	 */
	public static void logSAMLObject(final XMLObject object) {
		Element element = null;

		if (object instanceof SignableSAMLObject && ((SignableSAMLObject)object).isSigned() && object.getDOM() != null) {
			element = object.getDOM();
		} else {
			try {
				Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
				out.marshall(object);
				element = object.getDOM();

			} catch (MarshallingException e) {
				logger.error(e.getMessage(), e);
			}
		}

		try {
			Transformer transformer = TransformerFactory.newInstance().newTransformer();
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			StreamResult result = new StreamResult(new StringWriter());
			DOMSource source = new DOMSource(element);

			transformer.transform(source, result);
			String xmlString = result.getWriter().toString();

			logger.info(xmlString);
		} catch (TransformerConfigurationException e) {
			e.printStackTrace();
		} catch (TransformerException e) {
			e.printStackTrace();
		}
	}

}
