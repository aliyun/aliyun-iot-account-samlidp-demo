package com.aliyun.iotx.samldemo.configuration;

/**
 * IOT 环境类
 */
public enum Env {
    /**
     * 线上地址
     */
    ONLINE("https://account.aliplus.com/saml/sp/acs",
        "https://account.aliplus.com/saml/sp/metadata");

    String acsUrl;
    String audience;

    Env(String acsUrl, String audience) {
        this.acsUrl = acsUrl;
        this.audience = audience;
    }


    public String getAcsUrl() {
        return acsUrl;
    }

    public String getAudience() {
        return audience;
    }

}
