/**
 * The MIT License
 * Copyright (c) 2019- Nordic Institute for Interoperability Solutions (NIIS)
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
package org.niis.xroad.securityserver.restapi.converter;

import ee.ria.xroad.common.identifier.ClientId;
import ee.ria.xroad.common.identifier.SecurityServerId;

import com.google.common.collect.Streams;
import lombok.RequiredArgsConstructor;
import org.niis.xroad.restapi.converter.Converters;
import org.niis.xroad.restapi.openapi.BadRequestException;
import org.niis.xroad.restapi.util.FormatUtils;
import org.niis.xroad.securityserver.restapi.facade.GlobalConfFacade;
import org.niis.xroad.securityserver.restapi.openapi.model.SecurityServer;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Converter for security server (id) related data between openapi
 * and service domain classes
 */
@Component
@RequiredArgsConstructor
public class SecurityServerConverter {

    public static final int SECURITY_SERVER_CODE_INDEX = 3;

    private final ClientConverter clientConverter;
    private final GlobalConfFacade globalConfFacade;

    /**
     * encoded security server id =
     * <instance_id>:<member_class>:<member_code>:<security_server_code>
     * @param encodedId
     * @return
     */
    public SecurityServerId convertId(String encodedId) {
        validateEncodedString(encodedId);
        int serverCodeSeparatorIndex = encodedId.lastIndexOf(
                Converters.ENCODED_ID_SEPARATOR);
        // items 0,1,2 for a client id of an member (not a subsystem)
        String encodedMemberClientId = encodedId.substring(0, serverCodeSeparatorIndex);
        ClientId memberClientId = clientConverter.convertId(encodedMemberClientId);
        String serverCode = encodedId.substring(serverCodeSeparatorIndex + 1);
        SecurityServerId securityServerId = SecurityServerId.create(memberClientId, serverCode);
        return securityServerId;
    }

    private void validateEncodedString(String encodedId) {
        int separators = FormatUtils.countOccurences(encodedId,
                Converters.ENCODED_ID_SEPARATOR);
        if (separators != SECURITY_SERVER_CODE_INDEX) {
            throw new BadRequestException("Invalid security server id " + encodedId);
        }
    }

    /**
     * Convert securityServerId into encoded id
     * @param securityServerId
     * @return
     */
    public String convertId(SecurityServerId securityServerId) {
        ClientId ownerId = securityServerId.getOwner();
        StringBuilder builder = new StringBuilder();
        builder.append(clientConverter.convertId(ownerId));
        builder.append(Converters.ENCODED_ID_SEPARATOR);
        builder.append(securityServerId.getServerCode());
        return builder.toString();
    }

    /**
     * Convert SecurityServerId into SecurityServer
     * @param securityServerId
     * @return
     */
    public SecurityServer convert(SecurityServerId securityServerId) {
        SecurityServer securityServer = new SecurityServer();
        securityServer.setId(convertId(securityServerId));
        securityServer.setInstanceId(securityServerId.getXRoadInstance());
        securityServer.setMemberClass(securityServerId.getMemberClass());
        securityServer.setMemberCode(securityServerId.getMemberCode());
        securityServer.setServerCode(securityServerId.getServerCode());
        String securityServerAddress = globalConfFacade.getSecurityServerAddress(securityServerId);
        securityServer.setServerAddress(securityServerAddress);
        return securityServer;
    }

    /**
     * Convert a group of {@link SecurityServerId SecurityServerIds} into {@link SecurityServer SecurityServers}
     * @param securityServerIds
     * @return
     */
    public Set<SecurityServer> convert(Iterable<SecurityServerId> securityServerIds) {
        return Streams.stream(securityServerIds)
                .map(this::convert)
                .collect(Collectors.toSet());
    }

}
