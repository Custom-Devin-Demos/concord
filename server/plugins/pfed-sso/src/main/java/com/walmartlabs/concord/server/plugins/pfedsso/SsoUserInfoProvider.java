package com.walmartlabs.concord.server.plugins.pfedsso;

/*-
 * *****
 * Concord
 * -----
 * Copyright (C) 2017 - 2021 Walmart Inc.
 * -----
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =====
 */

import com.walmartlabs.concord.server.sdk.ConcordApplicationException;
import com.walmartlabs.concord.server.security.Roles;
import com.walmartlabs.concord.server.security.ldap.LdapPrincipal;
import com.walmartlabs.concord.server.user.AbstractUserInfoProvider;
import com.walmartlabs.concord.server.user.UserDao;
import com.walmartlabs.concord.server.user.UserType;

import javax.inject.Inject;
import java.util.Set;
import java.util.UUID;

public class SsoUserInfoProvider extends AbstractUserInfoProvider {

    private final SsoConfiguration cfg;

    @Inject
    public SsoUserInfoProvider(UserDao userDao, SsoConfiguration ssoConfiguration) {
        super(userDao);
        this.cfg = ssoConfiguration;
    }

    @Override
    public UserType getUserType() {
        return UserType.SSO;
    }

    @Override
    public UserInfo getInfo(UUID id, String username, String userDomain) {
        // return if ldap principal exists as part of sso
        LdapPrincipal ldapPrincipal = LdapPrincipal.getCurrent();
        if (ldapPrincipal != null && ldapPrincipal.getUsername().equalsIgnoreCase(username) && ldapPrincipal.getDomain().equalsIgnoreCase(userDomain)) {
            return UserInfo.builder()
                    .id(id)
                    .username(ldapPrincipal.getUsername())
                    .userDomain(ldapPrincipal.getDomain())
                    .displayName(ldapPrincipal.getDisplayName())
                    .email(ldapPrincipal.getEmail())
                    .groups(ldapPrincipal.getGroups())
                    .attributes(ldapPrincipal.getAttributes())
                    .build();
        }

        return getInfo(id, username, userDomain, UserType.LDAP);
    }

}
