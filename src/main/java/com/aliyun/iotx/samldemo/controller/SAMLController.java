package com.aliyun.iotx.samldemo.controller;

import com.aliyun.iotx.samldemo.configuration.Env;
import com.aliyun.iotx.samldemo.constants.AlgorithmMethod;
import com.aliyun.iotx.samldemo.constants.DigestMethod;
import com.aliyun.iotx.samldemo.util.EncodingUtils;
import com.aliyun.iotx.samldemo.util.IDPCredentials;
import com.aliyun.iotx.samldemo.util.OpenSamlImplementation;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.apache.commons.lang3.StringUtils;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.joda.time.DateTime;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.impl.XSAnyBuilder;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.messaging.context.*;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.opensaml.saml.saml2.binding.security.impl.SAML2HTTPRedirectDeflateSignatureSecurityHandler;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.metadata.*;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.impl.CollectionCredentialResolver;
import org.opensaml.xmlsec.SignatureValidationParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.BasicProviderKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.KeyInfoProvider;
import org.opensaml.xmlsec.keyinfo.impl.provider.DSAKeyValueProvider;
import org.opensaml.xmlsec.keyinfo.impl.provider.InlineX509DataProvider;
import org.opensaml.xmlsec.keyinfo.impl.provider.RSAKeyValueProvider;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

import static org.opensaml.saml.common.xml.SAMLConstants.SAML2_POST_BINDING_URI;
import static org.springframework.util.StringUtils.hasText;

@Controller
@RequestMapping("/saml")
public class SAMLController {
    /**
     * 应用的host
     */
    @Value("${iot.saml.host}")
    private volatile String host;

    @Value("${server.port}")
    private String port;

    /**
     * 公司 ID
     */
    @Value("${iot.saml.companyId}")
    private String companyId;

    /**
     * 判断用户是不理已经登陆的key
     */
    private String sessionKey = "loginKey";

    /**
     * 不需要修改的字段
     */
    private static final String TEMPLATE_PATH = "/templates/saml2-post-binding.vm";
    /**
     * 不需要修改的字段
     */
    @Resource
    private OpenSamlImplementation openSamlImplementation;

    private Env env = Env.ONLINE;

    @PostConstruct
    public void init(){
        if(!"80".equalsIgnoreCase(port)){
            host = host + ":" + port;
        }
    }


    /**
     * 注意, 生成元数据的时候,使 EntityID 字段与 Issuer 里面的值一致,否则会有问题!
     * @return
     * @throws MarshallingException
     * @throws SignatureException
     * @throws SecurityException
     */
    @RequestMapping("/metadata")
    @ResponseBody
    public ResponseEntity<ByteArrayResource> metadata()
        throws MarshallingException, SignatureException, SecurityException {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Cache-Control", "no-cache, no-store, must-revalidate");
        headers.add("Content-Disposition", "attachment; filename=" + System.currentTimeMillis() + ".xml");
        headers.add("Pragma", "no-cache");
        headers.add("Expires", "0");
        headers.add("Last-Modified", new Date().toString());
        headers.add("ETag", String.valueOf(System.currentTimeMillis()));

        return ResponseEntity
            .ok()
            .headers(headers)
            .contentType(MediaType.parseMediaType("application/octet-stream"))
            .body(new ByteArrayResource(this.generateIDPMetadataXML().getBytes()));


    }

    public String generateIDPMetadataXML() throws MarshallingException, SignatureException, SecurityException {
        EntityDescriptor entityDescriptor = openSamlImplementation.buildSAMLObject(EntityDescriptor.class);
        //EntityId是metadata地址
        String idpEntityId = host + "/saml/metadata";
        entityDescriptor.setEntityID(idpEntityId);
        //IDP用于SSO的描述符
        IDPSSODescriptor idpssoDescriptor = openSamlImplementation.buildSAMLObject(IDPSSODescriptor.class);
        //必须的
        idpssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
        //不加签
        idpssoDescriptor.setWantAuthnRequestsSigned(false);
        //用于验断言的 Key 信息生成
        KeyDescriptor keyDescriptor = openSamlImplementation.buildSAMLObject(KeyDescriptor.class);
        KeyInfoGenerator keyInfoGenerator = openSamlImplementation.getKeyInfoGenerator(openSamlImplementation.getSelfCredential());
        keyDescriptor.setUse(UsageType.SIGNING);
        keyDescriptor.setKeyInfo(keyInfoGenerator.generate(openSamlImplementation.getSelfCredential()));
        idpssoDescriptor.getKeyDescriptors().add(keyDescriptor);
        //IDP返回的NameIDFormat
        NameIDFormat nameIDFormat = openSamlImplementation.buildSAMLObject(NameIDFormat.class);
        nameIDFormat.setFormat(NameIDType.UNSPECIFIED);
        idpssoDescriptor.getNameIDFormats().add(nameIDFormat);
        //SSO地址相关
        SingleSignOnService singleSignOnService = openSamlImplementation.buildSAMLObject(SingleSignOnService.class);
        singleSignOnService.setBinding(SAML2_POST_BINDING_URI);
        //本次接入这个URL不需要使用
        singleSignOnService.setLocation(host + "/saml/sso");

        idpssoDescriptor.getSingleSignOnServices().add(singleSignOnService);
        entityDescriptor.getRoleDescriptors().add(idpssoDescriptor);

        return openSamlImplementation.transformSAMLObject2String(entityDescriptor);
    }


    /**
     * 用户的登陆页面,如果要实现免登录,此时在login验证通过后,将可向 iot 平台发起免登录数据(也称断言)
     * 具体方法是 httpPostBinding
     *
     * 强烈推荐在 HTTPS 链路上进行登录,以增强安全性
     *
     * @param request
     * @param response
     * @param username
     * @return
     * @throws MessageEncodingException
     * @throws ComponentInitializationException
     */
    @RequestMapping("/login")
    public ModelAndView login(HttpServletRequest request , HttpServletResponse response,
                        @RequestParam(value = "username", required = false) String username)
        throws MessageEncodingException, ComponentInitializationException {

        if(StringUtils.isNotBlank(username)){
            request.getSession().setAttribute(sessionKey, username);
            Response samlResponse = buildResponse(username,companyId, null
                ,OpenSamlImplementation.generateSecureRandomId());
            //对Reponse加签
            openSamlImplementation.signObject(samlResponse, AlgorithmMethod.RSA_SHA256, DigestMethod.RIPEMD160);
            //将用户浏览器跳转到IOT平台,此时IOT平台会建立登录态,然后在调回到,注册IDP时填写的 saml call back 地址
            httpPostBinding(null,response, env.getAcsUrl(), samlResponse);
            return null;
        }
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("login");
        modelAndView.addObject("msg","Welcome");
        return modelAndView;
    }

    /**
     * 模拟登录之后的页面
     *
     * @param request
     * @param response
     * @return
     * @throws IOException
     */
    @RequestMapping("/list")
    public Object list(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if(request.getSession().getAttribute(sessionKey) != null){
            ModelAndView modelAndView = new ModelAndView();
            modelAndView.setViewName("/list");
            modelAndView.addObject("user",request.getSession().getAttribute(sessionKey));
            return modelAndView;
        }else{
            response.sendRedirect("/saml/login");
            return null;
        }
    }

    /**
     * 一般的情况下用不到,因为 IOT 场景是 IDP 主动颁发断言,而不是 SP 主动发起 AuthnRequest
     * @param saml
     * @param relayState
     * @param httpServletRequest
     * @param httpSevletResponse
     * @throws MessageEncodingException
     * @throws ComponentInitializationException
     */
    @RequestMapping("/sso")
    public void sso(@RequestParam(value = "SAMLRequest") String saml,
                    @RequestParam(value = "RelayState",required = false)String relayState,
                    HttpServletRequest httpServletRequest,
                    HttpServletResponse httpSevletResponse
    ) throws MessageEncodingException, ComponentInitializationException, IOException, MessageHandlerException {
        String samlRequest = EncodingUtils.inflate(EncodingUtils.decode(saml));
        AuthnRequest authnRequest = (AuthnRequest)openSamlImplementation.transferXML2SAMLObject(samlRequest);
        validateSignature(httpServletRequest, authnRequest , authnRequest.getIssuer().getValue());

        String acsUrl = authnRequest.getAssertionConsumerServiceURL();
        String reqId = authnRequest.getID();
        String messageId = OpenSamlImplementation.generateSecureRandomId();
        //进行业务逻辑判断要登录的名称
        String defaultName = "name";
        Response response = buildResponse(defaultName,this.companyId, reqId, messageId);
        httpServletRequest.getSession().setAttribute(sessionKey, "来自SP发起的顺便建立的登录态的账号");
        openSamlImplementation.signObject(response, AlgorithmMethod.RSA_SHA256, DigestMethod.RIPEMD160);
        httpPostBinding(relayState, httpSevletResponse, acsUrl, response);

    }


    /**
     * 只适用于 SAML2HTTPRedirectDeflate的方式,对于POST不支持
     * @param httpServletRequest
     * @param authnRequest
     * @param spEntityId
     * @throws ComponentInitializationException
     * @throws MessageHandlerException
     * @throws IOException
     */
    public void validateSignature(HttpServletRequest httpServletRequest, AuthnRequest authnRequest,String spEntityId)
        throws ComponentInitializationException, MessageHandlerException, IOException {
        MessageContext context = new MessageContext();
        context.setMessage(authnRequest);

        SAMLMessageInfoContext samlMessageInfoContext = context.getSubcontext(SAMLMessageInfoContext.class,true);
        samlMessageInfoContext.setMessageIssueInstant(authnRequest.getIssueInstant());


        SAMLPeerEntityContext samlPeerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);
        samlPeerEntityContext.setRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);


        SAMLProtocolContext samlProtocolContext = context.getSubcontext(SAMLProtocolContext.class, true);
        samlProtocolContext.setProtocol(SAMLConstants.SAML2_REDIRECT_BINDING_URI);

        SecurityParametersContext securityParametersContext = context.getSubcontext(SecurityParametersContext.class,true);

        SignatureValidationParameters signatureValidationParameters = new SignatureValidationParameters();

        //TODO 解析发送请求的 SP 的元数据中的证书形成 Credential

        ArrayList<KeyInfoProvider> providers = new ArrayList<KeyInfoProvider>();
        providers.add( new RSAKeyValueProvider() );
        providers.add( new DSAKeyValueProvider() );
        providers.add( new InlineX509DataProvider() );
        BasicProviderKeyInfoCredentialResolver resolver = new BasicProviderKeyInfoCredentialResolver(providers);
        Credential signCer = readSPCredential();
        ((BasicCredential)signCer).setUsageType(UsageType.SIGNING);
        ((BasicCredential)signCer).setEntityId(spEntityId);
        CollectionCredentialResolver credentialResolver = new CollectionCredentialResolver(Arrays.asList(signCer));

        //MetadataCredentialResolver metadataCredentialResolver = new MetadataCredentialResolver();
        //metadataCredentialResolver.setRoleDescriptorResolver();
        //metadataCredentialResolver.setKeyInfoCredentialResolver(resolver);

        SignatureTrustEngine signatureTrustEngine = new ExplicitKeySignatureTrustEngine(credentialResolver, resolver);
        signatureValidationParameters.setSignatureTrustEngine(signatureTrustEngine);
        securityParametersContext.setSignatureValidationParameters(signatureValidationParameters);

        SAML2HTTPRedirectDeflateSignatureSecurityHandler securityHandler = new SAML2HTTPRedirectDeflateSignatureSecurityHandler();
        securityHandler.setHttpServletRequest(httpServletRequest);
        securityHandler.initialize();
        securityHandler.invoke(context);
    }

    /**
     * 这个就是IOT的证书,通过元数据可以获取 地址 https://account.aliplus.com/saml/sp/metadata
     * @return
     * @throws IOException
     */
    public Credential readSPCredential() throws IOException {
        return IDPCredentials.readCredential(SAMLController.class.getResourceAsStream("/spcredential"));
    }

    /**
     * 免登录的关键代码
     *
     * @param reqId
     * @param messageId
     * @return
     */
    private Response buildResponse(String loginName,String companyId, String reqId, String messageId) {
        Assertion assertion = openSamlImplementation.buildSAMLObject(Assertion.class);
        DateTime now = new DateTime();
        // 断言相关,随便生成的字符串
        assertion.setID(messageId);
        //必须元素,代表要登录iot平台的账号主体
        Subject subject = openSamlImplementation.buildSAMLObject(Subject.class);
        //必须元素,代表要登录的账号主要的用户名
        NameID nameID = openSamlImplementation.buildSAMLObject(NameID.class);
        nameID.setValue(loginName);
        nameID.setFormat(NameIDType.PERSISTENT);
        subject.setNameID(nameID);
        //必须元素 SubjectConfirmationData 的 Method统一为 METHOD_BEARER
        SubjectConfirmation subjectConfirmation = openSamlImplementation.buildSAMLObject(SubjectConfirmation.class);
        SubjectConfirmationData subjectConfirmationData = openSamlImplementation.buildSAMLObject(SubjectConfirmationData.class);
        if(StringUtils.isNotBlank(reqId)) {
            subjectConfirmationData.setInResponseTo(reqId);
        }
        subjectConfirmationData.setNotOnOrAfter(now.plusMinutes(5));
        //Recipient设置为IOT的域名
        subjectConfirmationData.setRecipient(env.getAcsUrl());
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
        subject.getSubjectConfirmations().add(subjectConfirmation);
        assertion.setSubject(subject);
        assertion.getAuthnStatements().add(getAuthnStatement(messageId));
        assertion.setIssueInstant(now);
        //issuer的值与entityId一致 必须元素
        assertion.setIssuer(idpBuildIssuer());
        assertion.setIssueInstant(now);
        //必须元素
        Conditions conditions = openSamlImplementation.buildSAMLObject(Conditions.class);
        conditions.setNotBefore(now);
        conditions.setNotOnOrAfter(now.plusSeconds(5));
        AudienceRestriction audienceRestriction = openSamlImplementation.buildSAMLObject(AudienceRestriction.class);
        //必须元素
        Audience audience = openSamlImplementation.buildSAMLObject(Audience.class);
        //固定
        audience.setAudienceURI(env.getAudience());
        audienceRestriction.getAudiences().add(audience);
        conditions.getAudienceRestrictions().add(audienceRestriction);
        assertion.setConditions(conditions);

        //名称为 companyId 是 Attribute 是必须元素,代表公司ID
        AttributeStatement attributeStatement =  openSamlImplementation.buildSAMLObject(AttributeStatement.class);
        Attribute attribute = openSamlImplementation.buildSAMLObject(Attribute.class);
        attribute.setName("companyId");
        XSAny attributeValue =  new XSAnyBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME);
        attributeValue.setTextContent(companyId);
        attribute.getAttributeValues().add(attributeValue);
        attributeStatement.getAttributes().add(attribute);

        assertion.getAttributeStatements().add(attributeStatement);

        Response response = openSamlImplementation.buildSAMLObject(Response.class);
        response.setID(OpenSamlImplementation.generateSecureRandomId());
        Status status = openSamlImplementation.buildSAMLObject(Status.class);
        StatusCode statusCode = openSamlImplementation.buildSAMLObject(StatusCode.class);
        //Status Code 要设置成SUCEESS
        statusCode.setValue(StatusCode.SUCCESS);
        status.setStatusCode(statusCode);

        response.setStatus(status);
        //DESTION设置成IOT的ACS
        response.setDestination(env.getAcsUrl());
        response.getAssertions().add(assertion);
        response.setIssueInstant(now);
        response.setIssuer(this.idpBuildIssuer());
        response.setVersion(SAMLVersion.VERSION_20);
        //对断言加签
        openSamlImplementation.signObject(assertion, AlgorithmMethod.RSA_SHA256, DigestMethod.RIPEMD160);
        return response;
    }

    private AuthnStatement getAuthnStatement(String msgId){
        AuthnStatement authnStatement = openSamlImplementation.buildSAMLObject(AuthnStatement.class);
        AuthnContext authnContext = openSamlImplementation.buildSAMLObject(AuthnContext.class);
        AuthnContextClassRef authnContextClassRef = openSamlImplementation.buildSAMLObject(AuthnContextClassRef.class);
        authnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
        authnContext.setAuthnContextClassRef(authnContextClassRef);
        authnStatement.setAuthnContext(authnContext);
        authnStatement.setAuthnInstant(new DateTime());
        //当从 SP 登出时 需要通过 SessionIndex 来确定出会话
        authnStatement.setSessionIndex(msgId);

        return authnStatement;
    }

    public Issuer idpBuildIssuer() {
        Issuer issuer = openSamlImplementation.buildSAMLObject(Issuer.class);
        String idpEntityId = host + "/saml/metadata";
        issuer.setValue(idpEntityId);
        return issuer;
    }

    /**
     * HTTP POST BINDING 时用于编码返回结果并返回给浏览器
     * 使用其他方式返回时可以使用
     * 目前iot只支持 HTTPPostEncoder
     * {@link org.opensaml.saml.saml2.binding.encoding.impl.HTTPArtifactEncoder}
     * {@link org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder}
     * {@link org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder}
     * {@link org.opensaml.saml.saml2.binding.encoding.impl.HTTPSOAP11Encoder}
     * {@link org.opensaml.saml.saml2.binding.encoding.impl.HttpClientRequestSOAP11Encoder}
     * 等上类实现
     * @param relayState
     * @param res
     * @param acsUrl
     * @param response
     * @throws ComponentInitializationException
     * @throws MessageEncodingException
     */
    private void httpPostBinding(String relayState,
                                 HttpServletResponse res, String acsUrl, Response response)
        throws ComponentInitializationException, MessageEncodingException {
        // HTTP相关的类不放到 openSamlImplementation 中
        MessageContext messageContext = new MessageContext();
        messageContext.setMessage(response);
        if(hasText(relayState)) {
            messageContext.getSubcontext(SAMLBindingContext.class,true).setRelayState(relayState);
        }
        SAMLEndpointContext samlEndpointContext = messageContext.getSubcontext(SAMLPeerEntityContext.class,true).getSubcontext(SAMLEndpointContext.class,true);
        Endpoint endpoint = openSamlImplementation.buildSAMLObject(AssertionConsumerService.class);
        endpoint.setLocation(acsUrl);
        samlEndpointContext.setEndpoint(endpoint);
        //openSamlImplementation.
        HTTPPostEncoder httpPostEncoder = new HTTPPostEncoder();
        httpPostEncoder.setMessageContext(messageContext);
        httpPostEncoder.setVelocityEngine(velocityEngine);
        httpPostEncoder.setVelocityTemplateId(TEMPLATE_PATH);
        httpPostEncoder.setHttpServletResponse(res);
        httpPostEncoder.initialize();
        httpPostEncoder.encode();
    }

    /**
     * Velocity 引擎
     */
    private VelocityEngine velocityEngine;

    public SAMLController() {
        velocityEngine = new VelocityEngine();
        velocityEngine.setProperty(RuntimeConstants.ENCODING_DEFAULT,
            "UTF-8");
        velocityEngine.setProperty(RuntimeConstants.OUTPUT_ENCODING,
            "UTF-8");
        velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER,
            "classpath");
        velocityEngine
            .setProperty("classpath.resource.loader.class",
                "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
        velocityEngine.init();
    }


}
