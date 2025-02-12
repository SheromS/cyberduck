package ch.cyberduck.core.diagnostics;

/*
 * Copyright (c) 2002-2015 David Kocher. All rights reserved.
 * http://cyberduck.ch/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Bug fixes, suggestions and comments should be sent to feedback@cyberduck.ch
 */

import ch.cyberduck.core.Host;
import ch.cyberduck.core.TestProtocol;

import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Ignore
public class DefaultInetAddressReachabilityTest {

    @Test
    public void testIsReachable() {
        final Reachability r = new DefaultInetAddressReachability();
        assertTrue(r.isReachable(
                new Host(new TestProtocol(), "cloud.iterate.ch")
        ));
    }

    @Test
    public void testNotReachableSubdomain() {
        final Reachability r = new DefaultInetAddressReachability();
        assertFalse(r.isReachable(
                new Host(new TestProtocol(), "a.cyberduck.ch")
        ));
    }

    @Test
    public void testNotReachableWrongHostname() {
        final Reachability r = new DefaultInetAddressReachability();
        assertFalse(r.isReachable(
                new Host(new TestProtocol(), "cyberduck.ch.f")
        ));
    }
}