/**
 * The MIT License
 * Copyright (c) 2018 Estonian Information System Authority (RIA),
 * Nordic Institute for Interoperability Solutions (NIIS), Population Register Centre (VRK)
 * Copyright (c) 2015-2017 Estonian Information System Authority (RIA), Population Register Centre (VRK)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.niis.xroad.restapi.config.audit;

/**
 * Known audit events for this module
 */
public enum RestApiAuditEvent {

    FORM_LOGIN("Log in user"),
    FORM_LOGOUT("Log out user"),

    KEY_MANAGEMENT_PAM_LOGIN("Key management API log in"),
    API_KEY_AUTHENTICATION("API key authentication"),
    AUTH_CREDENTIALS_DISCOVERY("Auth credentials discovery"),

    API_KEY_CREATE("API key create"),
    API_KEY_UPDATE("API key update"),
    API_KEY_REMOVE("API key remove"),

    INIT_ANCHOR("Initialize anchor"),
    INIT_SERVER_CONFIGURATION("Initialize server configuration"),

    // clients events
    ADD_CLIENT("Add client"),
    REGISTER_CLIENT("Register client"),
    UNREGISTER_CLIENT("Unregister client"),
    DELETE_CLIENT("Delete client"),
    DELETE_ORPHANS("Delete orphaned client keys, certs and certificates"),
    SEND_OWNER_CHANGE_REQ("Change owner"),
    ADD_SERVICE_DESCRIPTION("Add service description"),
    DELETE_SERVICE_DESCRIPTION("Delete service description"),
    DISABLE_SERVICE_DESCRIPTION("Disable service description"),
    ENABLE_SERVICE_DESCRIPTION("Enable service description"),
    REFRESH_SERVICE_DESCRIPTION("Refresh service description"),
    EDIT_SERVICE_DESCRIPTION("Edit service description"),
    EDIT_SERVICE_PARAMS("Edit service parameters"),
    ADD_REST_ENDPOINT("Add rest endpoint"),
    EDIT_REST_ENDPOINT("Edit rest endpoint"),
    DELETE_REST_ENDPOINT("Delete rest endpoint"),
    ADD_SERVICE_ACCESS_RIGHTS("Add access rights to service"),
    REMOVE_SERVICE_ACCESS_RIGHTS("Remove access rights from service"),
    ADD_SERVICE_CLIENT_ACCESS_RIGHTS("Add access rights to subject"),
    REMOVE_SERVICE_CLIENT_ACCESS_RIGHTS("Remove access rights from subject"),
    SET_CONNECTION_TYPE("Set connection type for servers in service consumer role"),
    ADD_CLIENT_INTERNAL_CERT("Add internal TLS certificate"),
    DELETE_CLIENT_INTERNAL_CERT("Delete internal TLS certificate"),
    ADD_LOCAL_GROUP("Add group"),
    EDIT_LOCAL_GROUP_DESC("Edit group description"),
    ADD_LOCAL_GROUP_MEMBERS("Add members to group"),
    REMOVE_LOCAL_GROUP_MEMBERS("Remove members from group"),
    DELETE_LOCAL_GROUP("Delete group"),

    // system parameters
    GENERATE_INTERNAL_TLS_CSR("Generate certificate request for TLS"),
    IMPORT_INTERNAL_TLS_CERT("Import TLS certificate from file"),
    UPLOAD_ANCHOR("Upload configuration anchor"),
    ADD_TSP("Add timestamping service"),
    DELETE_TSP("Delete timestamping service"),
    GENERATE_INTERNAL_TLS_KEY_CERT("Generate new internal TLS key and certificate"),

    // keys and certificates events
    LOGIN_TOKEN("Log in to token"),
    LOGOUT_TOKEN("Log out from token"),
    CHANGE_PIN_TOKEN("Change token pin"),
    GENERATE_KEY("Generate key"),
    DELETE_KEY("Delete key"),
    DELETE_KEY_FROM_TOKEN_AND_CONFIG("Delete key from token and configuration"),
    GENERATE_CSR("Generate CSR"),
    DELETE_CSR("Delete CSR"),
    GENERATE_KEY_AND_CSR("Generate key and CSR"),

    IMPORT_CERT_FILE("Import certificate from file"),
    IMPORT_CERT_TOKEN("Import certificate from token"),
    DELETE_CERT("Delete certificate"),
    DELETE_CERT_FROM_CONFIG("Delete certificate from configuration"),
    DELETE_CERT_FROM_TOKEN("Delete certificate from token"),
    ACTIVATE_CERT("Enable certificate"),
    DISABLE_CERT("Disable certificate"),
    REGISTER_AUTH_CERT("Register authentication certificate"),
    UNREGISTER_AUTH_CERT("Unregister authentication certificate"),
    SKIP_UNREGISTER_AUTH_CERT("Skip unregistration of authentication certificate"),
    UPDATE_TOKEN_NAME("Set friendly name to token"),
    UPDATE_KEY_NAME("Set friendly name to key"),

    // backup and restore events
    BACKUP("Back up configuration"),
    UPLOAD_BACKUP("Upload backup file"),
    DELETE_BACKUP("Delete backup file"),
    RESTORE_BACKUP("Restore configuration"),

    UNSPECIFIED_ACCESS_CHECK("Access check"), // for AccessDeniedExceptions without more specific detail
    UNSPECIFIED_AUTHENTICATION("Authentication"); // for AuthenticationExceptions without more specific detail

    private final String eventName;

    RestApiAuditEvent(String eventName) {
        this.eventName = eventName;
    }

    public String getEventName() {
        return eventName;
    }
}
