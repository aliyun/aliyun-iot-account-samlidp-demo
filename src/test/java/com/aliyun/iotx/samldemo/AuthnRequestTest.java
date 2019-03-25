package com.aliyun.iotx.samldemo;

import com.aliyun.iotx.samldemo.constants.AlgorithmMethod;
import com.aliyun.iotx.samldemo.constants.DigestMethod;
import com.aliyun.iotx.samldemo.util.OpenSamlImplementation;
import org.joda.time.DateTime;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.saml2.binding.security.impl.SAML2HTTPPostSimpleSignSecurityHandler;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.security.credential.CredentialResolver;
import org.opensaml.security.credential.impl.StaticCredentialResolver;
import org.opensaml.xmlsec.SignatureValidationParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.BasicProviderKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.provider.InlineX509DataProvider;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import javax.annotation.Resource;

import java.util.Arrays;

import static org.opensaml.saml.common.xml.SAMLConstants.SAML2_POST_BINDING_URI;

/**
 * @author @aliababa-inc.com
 * @date 2019/3/2
 */
@RunWith(SpringRunner.class)
@SpringBootTest
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AuthnRequestTest {
    String dest = "http://localhost:8888/saml/sso";
    String spAcsUrl = "http://localhost:8888/saml/acs";
    String spEntityId = "entityId";
    @Resource
    OpenSamlImplementation implementation;
    private static AuthnRequest request;

    @Test
    public void aTest() throws MarshallingException {
        AuthnRequest authnRequest = implementation.buildSAMLObject(AuthnRequest.class);
        //请求时间：该对象创建的时间，以判断其时效性
        authnRequest.setIssueInstant(new DateTime());
        //目标URL：目标地址，IDP地址
        authnRequest.setDestination(dest);
        //传输SAML断言所需要的绑定：也就是用何种协议使用Artifact来取回真正的认证信息，
        authnRequest.setProtocolBinding(SAML2_POST_BINDING_URI);
        //SP地址： 也就是SAML断言返回的地址
        authnRequest.setAssertionConsumerServiceURL(this.spAcsUrl);
        //请求的ID：为当前请求设置ID，一般为随机数
        authnRequest.setID(OpenSamlImplementation.generateSecureRandomId());
        //Issuer： 发行人信息，也就是SP的ID，一般是SP的URL
        authnRequest.setIssuer(spBuildIssuer());
        //NameID：IDP对于用户身份的标识；NameID policy是SP关于NameID是如何创建的说明
        authnRequest.setNameIDPolicy(buildNameIdPolicy());
        // 请求认证上下文（requested Authentication Context）:
        // SP对于认证的要求，包含SP希望IDP如何验证用户，也就是IDP要依据什么来验证用户身份。
        authnRequest.setRequestedAuthnContext(buildRequestedAuthnContext());


        implementation.signObject(authnRequest,AlgorithmMethod.RSA_SHA256,DigestMethod.RIPEMD160);

        request = authnRequest;
        System.out.println(implementation.transformSAMLObject2String(authnRequest));
    }

    @Test
    public void bValidate9(){
        //MessageContext context = new MessageContext<Response>();
        //context.setMessage(request);
        //
        //
        //SAML2HTTPPostSimpleSignSecurityHandler securityHandler = new SAML2HTTPPostSimpleSignSecurityHandler();
        //securityHandler.setHttpServletRequest(request);
        //securityHandler.setParser(implementation.getParserPool());
        //InlineX509DataProvider inlineX509DataProvider = new InlineX509DataProvider();
        //BasicProviderKeyInfoCredentialResolver basicProviderKeyInfoCredentialResolver =
        //    new BasicProviderKeyInfoCredentialResolver(Arrays.asList(inlineX509DataProvider));
        //securityHandler.setKeyInfoResolver(basicProviderKeyInfoCredentialResolver);
        //
        //SecurityParametersContext securityParametersContext = context.getSubcontext(SecurityParametersContext.class,true);
        //SignatureValidationParameters signatureValidationParameters = new SignatureValidationParameters();
        //KeyInfoCredentialResolver keyInfoCredentialResolver =
        //    new StaticKeyInfoCredentialResolver(openSamlImplementation.resolveCredentialByCertificate(extractX509StringFromSignable(response)));
        //CredentialResolver credentialResolver = new StaticCredentialResolver(openSamlImplementation.spCredential());
        //ExplicitKeySignatureTrustEngine signatureTrustEngine = new ExplicitKeySignatureTrustEngine(credentialResolver, keyInfoCredentialResolver);
        //signatureValidationParameters.setSignatureTrustEngine(signatureTrustEngine);
        //securityParametersContext.setSignatureValidationParameters(signatureValidationParameters);

    }

    public Issuer spBuildIssuer() {
        Issuer issuer = implementation.buildSAMLObject(Issuer.class);
        issuer.setValue(spEntityId);
        return issuer;
    }

    private NameIDPolicy buildNameIdPolicy() {
        NameIDPolicy nameIDPolicy = implementation.buildSAMLObject(NameIDPolicy.class);
        nameIDPolicy.setAllowCreate(true);
        nameIDPolicy.setFormat(NameIDType.TRANSIENT);
        return nameIDPolicy;
    }

    /**
     * SP发送Authn请求时调用
     * @return
     */
    private RequestedAuthnContext buildRequestedAuthnContext() {
        RequestedAuthnContext requestedAuthnContext = implementation.buildSAMLObject(RequestedAuthnContext.class);
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);

        AuthnContextClassRef passwordAuthnContextClassRef = implementation.buildSAMLObject(AuthnContextClassRef.class);
        passwordAuthnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);

        requestedAuthnContext.getAuthnContextClassRefs().add(passwordAuthnContextClassRef);

        return requestedAuthnContext;

    }

}
