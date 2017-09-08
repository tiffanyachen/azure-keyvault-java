/**
 * Code generated by Microsoft (R) AutoRest Code Generator 1.2.2.0
 * Changes may cause incorrect behavior and will be lost if the code is
 * regenerated.
 */

package com.microsoft.azure.keyvault.models;

import com.microsoft.rest.Base64Url;
import java.util.Map;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A certificate bundle consists of a certificate (X509) plus its attributes.
 */
public class CertificateBundle {
    /**
     * The certificate id.
     */
    @JsonProperty(value = "id", access = JsonProperty.Access.WRITE_ONLY)
    private String id;

    /**
     * The key id.
     */
    @JsonProperty(value = "kid", access = JsonProperty.Access.WRITE_ONLY)
    private String kid;

    /**
     * The secret id.
     */
    @JsonProperty(value = "sid", access = JsonProperty.Access.WRITE_ONLY)
    private String sid;

    /**
     * Thumbprint of the certificate.
     */
    @JsonProperty(value = "x5t", access = JsonProperty.Access.WRITE_ONLY)
    private Base64Url x509Thumbprint;

    /**
     * The management policy.
     */
    @JsonProperty(value = "policy", access = JsonProperty.Access.WRITE_ONLY)
    private CertificatePolicy policy;

    /**
     * CER contents of x509 certificate.
     */
    @JsonProperty(value = "cer")
    private byte[] cer;

    /**
     * The content type of the secret.
     */
    @JsonProperty(value = "contentType")
    private String contentType;

    /**
     * The certificate attributes.
     */
    @JsonProperty(value = "attributes")
    private CertificateAttributes attributes;

    /**
     * Application specific metadata in the form of key-value pairs.
     */
    @JsonProperty(value = "tags")
    private Map<String, String> tags;

    /**
     * Get the id value.
     *
     * @return the id value
     */
    public String id() {
        return this.id;
    }

    /**
     * Get the kid value.
     *
     * @return the kid value
     */
    public String kid() {
        return this.kid;
    }

    /**
     * Get the sid value.
     *
     * @return the sid value
     */
    public String sid() {
        return this.sid;
    }

    /**
     * Get the x509Thumbprint value.
     *
     * @return the x509Thumbprint value
     */
    public byte[] x509Thumbprint() {
        if (this.x509Thumbprint == null) {
            return null;
        }
        return this.x509Thumbprint.decodedBytes();
    }

    /**
     * Get the policy value.
     *
     * @return the policy value
     */
    public CertificatePolicy policy() {
        return this.policy;
    }

    /**
     * Get the cer value.
     *
     * @return the cer value
     */
    public byte[] cer() {
        return this.cer;
    }

    /**
     * Set the cer value.
     *
     * @param cer the cer value to set
     * @return the CertificateBundle object itself.
     */
    public CertificateBundle withCer(byte[] cer) {
        this.cer = cer;
        return this;
    }

    /**
     * Get the contentType value.
     *
     * @return the contentType value
     */
    public String contentType() {
        return this.contentType;
    }

    /**
     * Set the contentType value.
     *
     * @param contentType the contentType value to set
     * @return the CertificateBundle object itself.
     */
    public CertificateBundle withContentType(String contentType) {
        this.contentType = contentType;
        return this;
    }

    /**
     * Get the attributes value.
     *
     * @return the attributes value
     */
    public CertificateAttributes attributes() {
        return this.attributes;
    }

    /**
     * Set the attributes value.
     *
     * @param attributes the attributes value to set
     * @return the CertificateBundle object itself.
     */
    public CertificateBundle withAttributes(CertificateAttributes attributes) {
        this.attributes = attributes;
        return this;
    }

    /**
     * Get the tags value.
     *
     * @return the tags value
     */
    public Map<String, String> tags() {
        return this.tags;
    }

    /**
     * Set the tags value.
     *
     * @param tags the tags value to set
     * @return the CertificateBundle object itself.
     */
    public CertificateBundle withTags(Map<String, String> tags) {
        this.tags = tags;
        return this;
    }

}
