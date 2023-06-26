package ch.cyberduck.core.s3;

/*
 * Copyright (c) 2002-2018 iterate GmbH. All rights reserved.
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
import ch.cyberduck.core.DisabledCancelCallback;
import ch.cyberduck.core.Host;
import ch.cyberduck.core.LoginCallback;
import ch.cyberduck.core.exception.BackgroundException;
import ch.cyberduck.core.exception.ExpiredTokenException;
import ch.cyberduck.core.exception.InteroperabilityException;
import ch.cyberduck.core.exception.LoginCanceledException;
import ch.cyberduck.core.exception.LoginFailureException;
import ch.cyberduck.core.http.DisabledServiceUnavailableRetryStrategy;
import ch.cyberduck.core.oauth.OAuth2RequestInterceptor;
import ch.cyberduck.core.ssl.X509KeyManager;
import ch.cyberduck.core.ssl.X509TrustManager;
import ch.cyberduck.core.sts.AssumeRoleWithWebIdentitySTSCredentialsConfigurator;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.protocol.HttpContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jets3t.service.security.AWSSessionCredentials;

public class S3WebIdentityTokenExpiredResponseInterceptor extends DisabledServiceUnavailableRetryStrategy {
    private static final Logger log = LogManager.getLogger(S3WebIdentityTokenExpiredResponseInterceptor.class);

    private static final int MAX_RETRIES = 1;

    private final S3Session session;
    private final Host host;
    private final AssumeRoleWithWebIdentitySTSCredentialsConfigurator configurator;
    private final OAuth2RequestInterceptor authorizationService;

    private final LoginCallback prompt;

    public S3WebIdentityTokenExpiredResponseInterceptor(final S3Session session, final X509TrustManager trust,
                                                        final X509KeyManager key, final LoginCallback prompt,
                                                        OAuth2RequestInterceptor authorizationService) {
        this.session = session;
        this.host = session.getHost();
        this.configurator = new AssumeRoleWithWebIdentitySTSCredentialsConfigurator(trust, key, prompt);
        this.authorizationService = authorizationService;
    }

    @Override
    public boolean retryRequest(final HttpResponse response, final int executionCount, final HttpContext context) {
        if(executionCount <= MAX_RETRIES) {
            switch(response.getStatusLine().getStatusCode()) {
                case HttpStatus.SC_FORBIDDEN:
                    try {
                        session.refreshOAuthTokens();
                        Credentials credentials = configurator.configure(host);
                        session.getClient().setProviderCredentials(credentials.isAnonymousLogin() ? null :
                                new AWSSessionCredentials(credentials.getUsername(), credentials.getPassword(),
                                        credentials.getToken()));
                        System.out.println(session.getClient().getProviderCredentials().getAccessKey());
                        return true;
                    }
                    catch(LoginFailureException | LoginCanceledException e) {
                        log.warn(String.format("Attempt to renew expired token failed. %s", e.getMessage()));
                    }
                    catch(BackgroundException e) {
                        throw new RuntimeException(e);
                    }
            }
        }
        else {
            if(log.isWarnEnabled()) {
                log.warn(String.format("Skip retry for response %s after %d executions", response, executionCount));
            }
        }
        return false;
    }
}