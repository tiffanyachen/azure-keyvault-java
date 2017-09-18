/**
 * Code generated by Microsoft (R) AutoRest Code Generator 1.2.2.0
 * Changes may cause incorrect behavior and will be lost if the code is
 * regenerated.
 */

package com.microsoft.azure.keyvault.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.azure.keyvault.CertificateOperationIdentifier;

import java.io.IOException;

/**
 * A certificate operation is returned in case of asynchronous requests.
 */
public class CertificateOperation extends com.microsoft.azure.keyvault.models.generated.CertificateOperation<CertificateOperation> {

    /**
     * The certificate operation identifier.
     * @return the identifier value
     */
    public CertificateOperationIdentifier certificateOperationIdentifier() {
        if (id() == null || id().isEmpty()) {
            return null;
        }
        return new CertificateOperationIdentifier(id());
    }

    @Override
    public String toString() {
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.writeValueAsString(this);
        } catch (JsonGenerationException e) {
            throw new IllegalStateException(e);
        } catch (JsonMappingException e) {
            throw new IllegalStateException(e);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
