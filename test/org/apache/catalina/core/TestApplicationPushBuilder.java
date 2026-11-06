/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.catalina.core;

import java.lang.reflect.Field;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import javax.servlet.http.Cookie;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.connector.Connector;
import org.apache.catalina.connector.Response;
import org.apache.coyote.ActionCode;
import org.apache.coyote.ActionHook;
import org.apache.tomcat.unittest.TesterRequest;

public class TestApplicationPushBuilder {

    @Test
    public void test01() {
        doTest("foo", StandardCharsets.UTF_8, "foo");
    }

    @Test
    public void test02() {
        doTest("/foo", StandardCharsets.UTF_8, "/foo");
    }

    @Test
    public void test03() {
        doTest("%20foo", StandardCharsets.UTF_8, " foo");
    }

    @Test
    public void test04() {
        doTest("fo%20o", StandardCharsets.UTF_8, "fo o");
    }

    @Test
    public void test05() {
        doTest("foo%20", StandardCharsets.UTF_8, "foo ");
    }

    @Test
    public void test06() {
        doTest("%21foo", StandardCharsets.UTF_8, "!foo");
    }

    @Test
    public void test07() {
        doTest("fo%21o", StandardCharsets.UTF_8, "fo!o");
    }

    @Test
    public void test08() {
        doTest("foo%21", StandardCharsets.UTF_8, "foo!");
    }


    @Test
    public void testPushSessionPathParameterNotInDecodedUri() throws Exception {
        /*
         * Push requests are processed by CoyoteAdapter as in-memory requests.
         * Since the fix for CVE-2025-31651 CoyoteAdapter no longer removes path
         * parameters from the decodedURI of an in-memory request, so the
         * session path parameter added to the push path must not be present in
         * the decodedURI of the push request (it is still present in the
         * requestURI and as a path parameter).
         */
        final org.apache.coyote.Request[] pushTarget = new org.apache.coyote.Request[1];
        org.apache.coyote.Request coyoteRequest = new org.apache.coyote.Request();
        Field hook = org.apache.coyote.Request.class.getDeclaredField("hook");
        hook.setAccessible(true);
        hook.set(coyoteRequest, new ActionHook() {
            @Override
            public void action(ActionCode actionCode, Object param) {
                if (actionCode == ActionCode.PUSH_REQUEST) {
                    pushTarget[0] = (org.apache.coyote.Request) param;
                }
            }
        });

        // Not named connector as that would be hidden by Request.connector
        final Connector testConnector = new Connector();
        TesterRequest request = new TesterRequest(true) {
            @Override
            public Connector getConnector() {
                return testConnector;
            }
            @Override
            public Cookie[] getCookies() {
                return null;
            }
        };
        request.setCoyoteRequest(coyoteRequest);
        request.setResponse(new Response());

        ApplicationPushBuilder pushBuilder = new ApplicationPushBuilder(request, request);
        pushBuilder.path("/foo%20bar/x.css").push();

        Assert.assertNotNull(pushTarget[0]);
        Assert.assertEquals("/foo%20bar/x.css;jsessionid=1234", pushTarget[0].requestURI().toString());
        Assert.assertEquals("/foo bar/x.css", pushTarget[0].decodedURI().toString());
        Assert.assertEquals("1234", pushTarget[0].getPathParameter("jsessionid"));
    }


    private void doTest(String input, Charset charset, String expected) {
        String result = ApplicationPushBuilder.decode(input, charset);
        Assert.assertEquals(expected, result);
    }
}
