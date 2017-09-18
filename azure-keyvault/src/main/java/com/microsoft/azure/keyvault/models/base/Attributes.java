/**
 * Code generated by Microsoft (R) AutoRest Code Generator 1.2.2.0
 * Changes may cause incorrect behavior and will be lost if the code is
 * regenerated.
 */

package com.microsoft.azure.keyvault.models.base;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

/**
 * The object attributes managed by the KeyVault service.
 */
public abstract class Attributes<T extends Attributes<T>> {
    /**
     * Determines whether the object is enabled.
     */
    @JsonProperty(value = "enabled")
    private Boolean enabled;

    /**
     * Not before date in UTC.
     */
    @JsonProperty(value = "nbf")
    private Long notBefore;

    /**
     * Expiry date in UTC.
     */
    @JsonProperty(value = "exp")
    private Long expires;

    /**
     * Creation time in UTC.
     */
    @JsonProperty(value = "created", access = JsonProperty.Access.WRITE_ONLY)
    private Long created;

    /**
     * Last updated time in UTC.
     */
    @JsonProperty(value = "updated", access = JsonProperty.Access.WRITE_ONLY)
    private Long updated;

    /**
     * Get the enabled value.
     *
     * @return the enabled value
     */
    public Boolean enabled() {
        return this.enabled;
    }

    /**
     * Set the enabled value.
     *
     * @param enabled the enabled value to set
     * @return the Attributes object itself.
     */
    public T withEnabled(Boolean enabled) {
        this.enabled = enabled;
        return (T) this;
    }

    /**
     * Get the notBefore value.
     *
     * @return the notBefore value
     */
    public DateTime notBefore() {
        if (this.notBefore == null) {
            return null;
        }
        return new DateTime(this.notBefore * 1000L, DateTimeZone.UTC);
    }

    /**
     * Set the notBefore value.
     *
     * @param notBefore the notBefore value to set
     * @return the Attributes object itself.
     */
    public T withNotBefore(DateTime notBefore) {
        if (notBefore == null) {
            this.notBefore = null;
        } else {
            this.notBefore = notBefore.toDateTime(DateTimeZone.UTC).getMillis() / 1000;
        }
        return (T) this;
    }

    /**
     * Get the expires value.
     *
     * @return the expires value
     */
    public DateTime expires() {
        if (this.expires == null) {
            return null;
        }
        return new DateTime(this.expires * 1000L, DateTimeZone.UTC);
    }

    /**
     * Set the expires value.
     *
     * @param expires the expires value to set
     * @return the Attributes object itself.
     */
    public T withExpires(DateTime expires) {
        if (expires == null) {
            this.expires = null;
        } else {
            this.expires = expires.toDateTime(DateTimeZone.UTC).getMillis() / 1000;
        }
        return (T) this;
    }

    /**
     * Get the created value.
     *
     * @return the created value
     */
    public DateTime created() {
        if (this.created == null) {
            return null;
        }
        return new DateTime(this.created * 1000L, DateTimeZone.UTC);
    }

    /**
     * Get the updated value.
     *
     * @return the updated value
     */
    public DateTime updated() {
        if (this.updated == null) {
            return null;
        }
        return new DateTime(this.updated * 1000L, DateTimeZone.UTC);
    }

}
