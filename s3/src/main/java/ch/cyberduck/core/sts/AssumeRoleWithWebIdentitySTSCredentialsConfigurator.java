package ch.cyberduck.core.sts;/*
 * Copyright (c) 2002-2023 iterate GmbH. All rights reserved.
 * https://cyberduck.io/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

import ch.cyberduck.core.Credentials;
import ch.cyberduck.core.Host;
import ch.cyberduck.core.PasswordCallback;
import ch.cyberduck.core.ssl.X509KeyManager;
import ch.cyberduck.core.ssl.X509TrustManager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AnonymousAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithWebIdentityRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithWebIdentityResult;

public class AssumeRoleWithWebIdentitySTSCredentialsConfigurator extends AWSProfileSTSCredentialsConfigurator {
    private static final Logger log = LogManager.getLogger(AssumeRoleWithWebIdentitySTSCredentialsConfigurator.class);

    public AssumeRoleWithWebIdentitySTSCredentialsConfigurator(final X509TrustManager trust, final X509KeyManager key, final PasswordCallback prompt) {
        super(trust, key, prompt);
    }

    @Override
    public Credentials configure(final Host host) {
        final Credentials credentials = new Credentials(host.getCredentials());

        // TODO what about region?
        final AWSSecurityTokenService service = this.getTokenService(host, null, null, null, null);

        // TODO why do we have accessToken==null in some cases - or does this come from inconsistent policies which lead to read errors and then discarding credentials? Needs more debugging.
        String accessToken = credentials.getOauth().getAccessToken();
        AssumeRoleWithWebIdentityRequest webIdReq = new AssumeRoleWithWebIdentityRequest()
                .withWebIdentityToken(accessToken)
                .withDurationSeconds(host.getProtocol().getSTSDurationSeconds())
                .withRoleSessionName(host.getProtocol().getSTSRoleSessionName());
        if(host.getProtocol().getSTSPolicy() != null) {
            webIdReq = webIdReq.withPolicy(host.getProtocol().getSTSPolicy());
        }
        if(host.getProtocol().getSTSRoleArn() != null) {
            webIdReq = webIdReq.withRoleArn(host.getProtocol().getSTSRoleArn());
        }


        if(log.isDebugEnabled()) {
            log.debug("Assuming role with web identity for host: {}", host);
        }


        try {
            AssumeRoleWithWebIdentityResult result = service.assumeRoleWithWebIdentity(webIdReq);
            com.amazonaws.services.securitytoken.model.Credentials cred = result.getCredentials();

            if(log.isDebugEnabled()) {
                log.debug(cred.toString());
            }

            credentials.setUsername(cred.getAccessKeyId());
            credentials.setUsername(cred.getAccessKeyId());
            credentials.setPassword(cred.getSecretAccessKey());
            credentials.setToken(cred.getSessionToken());

            return credentials;
        }
        catch(Exception e) {
            log.error(String.format("Error while Assuming Role with Web Identity from STS %s for %s", host.getProtocol().getSTSEndpoint(), host.getHostname()), e);
            throw e;
        }

    }

    @Override
    public AWSSecurityTokenService getTokenService(final Host host, final String region, final String accessKey, final String secretKey, final String sessionToken) {
        return AWSSecurityTokenServiceClientBuilder
                .standard()
                .withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration(host.getProtocol().getSTSEndpoint(), null))
                .withCredentials(new AWSCredentialsProvider() {
                    @Override
                    public AWSCredentials getCredentials() {
                        return new AnonymousAWSCredentials();
                    }

                    @Override
                    public void refresh() {

                    }
                })
                .build();
    }
}
