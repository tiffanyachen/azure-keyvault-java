/**
 * Code generated by Microsoft (R) AutoRest Code Generator 1.2.2.0
 * Changes may cause incorrect behavior and will be lost if the code is
 * regenerated.
 */

package com.microsoft.azure.keyvault.models;

import java.util.List;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The certificate list result.
 */
public class CertificateListResult {
    /**
     * A response message containing a list of certificates in the key vault
     * along with a link to the next page of certificates.
     */
    @JsonProperty(value = "value", access = JsonProperty.Access.WRITE_ONLY)
    private List<CertificateItem> value;

    /**
     * The URL to get the next set of certificates.
     */
    @JsonProperty(value = "nextLink", access = JsonProperty.Access.WRITE_ONLY)
    private String nextLink;

    /**
     * Get the value value.
     *
     * @return the value value
     */
    public List<CertificateItem> value() {
        return this.value;
    }

    /**
     * Get the nextLink value.
     *
     * @return the nextLink value
     */
    public String nextLink() {
        return this.nextLink;
    }

}
