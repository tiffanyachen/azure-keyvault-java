/**
 * Code generated by Microsoft (R) AutoRest Code Generator 1.2.2.0
 * Changes may cause incorrect behavior and will be lost if the code is
 * regenerated.
 */

package com.microsoft.azure.keyvault.models.generated;

import java.util.Map;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.microsoft.azure.keyvault.models.KeyAttributes;
import com.microsoft.azure.keyvault.webkey.JsonWebKey;

/**
 * A KeyBundle consisting of a WebKey plus its attributes.
 */
public abstract class KeyBundle<T extends KeyBundle<T>>{
    /**
     * The Json web key.
     */
    @JsonProperty(value = "key")
    private JsonWebKey key;

    /**
     * The key management attributes.
     */
    @JsonProperty(value = "attributes")
    private KeyAttributes attributes;

    /**
     * Application specific metadata in the form of key-value pairs.
     */
    @JsonProperty(value = "tags")
    private Map<String, String> tags;

    /**
     * True if the key's lifetime is managed by key vault. If this is a key
     * backing a certificate, then managed will be true.
     */
    @JsonProperty(value = "managed", access = JsonProperty.Access.WRITE_ONLY)
    private Boolean managed;

    /**
     * Get the key value.
     *
     * @return the key value
     */
    public JsonWebKey key() {
        return this.key;
    }

    /**
     * Set the key value.
     *
     * @param key the key value to set
     * @return the KeyBundle object itself.
     */
    public T withKey(JsonWebKey key) {
        this.key = key;
        return (T) this;
    }

    /**
     * Get the attributes value.
     *
     * @return the attributes value
     */
    public KeyAttributes attributes() {
        return this.attributes;
    }

    /**
     * Set the attributes value.
     *
     * @param attributes the attributes value to set
     * @return the KeyBundle object itself.
     */
    public T withAttributes(KeyAttributes attributes) {
        this.attributes = attributes;
        return (T) this;
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
     * @return the KeyBundle object itself.
     */
    public T withTags(Map<String, String> tags) {
        this.tags = tags;
        return (T) this;
    }

    /**
     * Get the managed value.
     *
     * @return the managed value
     */
    public Boolean managed() {
        return this.managed;
    }

}
