/**
 * Code generated by Microsoft (R) AutoRest Code Generator 1.2.2.0
 * Changes may cause incorrect behavior and will be lost if the code is
 * regenerated.
 */

package com.microsoft.azure.keyvault.models;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A Deleted Secret consisting of its previous id, attributes and its tags, as
 * well as information on when it will be purged.
 */
public class DeletedSecretBundle extends SecretBundle {
    /**
     * The url of the recovery object, used to identify and recover the deleted
     * secret.
     */
    @JsonProperty(value = "recoveryId")
    private String recoveryId;

    /**
     * The time when the secret is scheduled to be purged, in UTC.
     */
    @JsonProperty(value = "scheduledPurgeDate", access = JsonProperty.Access.WRITE_ONLY)
    private Long scheduledPurgeDate;

    /**
     * The time when the secret was deleted, in UTC.
     */
    @JsonProperty(value = "deletedDate", access = JsonProperty.Access.WRITE_ONLY)
    private Long deletedDate;

    /**
     * Get the recoveryId value.
     *
     * @return the recoveryId value
     */
    public String recoveryId() {
        return this.recoveryId;
    }

    /**
     * Set the recoveryId value.
     *
     * @param recoveryId the recoveryId value to set
     * @return the DeletedSecretBundle object itself.
     */
    public DeletedSecretBundle withRecoveryId(String recoveryId) {
        this.recoveryId = recoveryId;
        return this;
    }

    /**
     * Get the scheduledPurgeDate value.
     *
     * @return the scheduledPurgeDate value
     */
    public DateTime scheduledPurgeDate() {
        if (this.scheduledPurgeDate == null) {
            return null;
        }
        return new DateTime(this.scheduledPurgeDate * 1000L, DateTimeZone.UTC);
    }

    /**
     * Get the deletedDate value.
     *
     * @return the deletedDate value
     */
    public DateTime deletedDate() {
        if (this.deletedDate == null) {
            return null;
        }
        return new DateTime(this.deletedDate * 1000L, DateTimeZone.UTC);
    }

}
