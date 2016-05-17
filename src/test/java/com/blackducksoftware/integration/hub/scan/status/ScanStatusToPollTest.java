/*******************************************************************************
 * Copyright (C) 2016 Black Duck Software, Inc.
 * http://www.blackducksoftware.com/
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *******************************************************************************/
package com.blackducksoftware.integration.hub.scan.status;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import nl.jqno.equalsverifier.EqualsVerifier;
import nl.jqno.equalsverifier.Warning;

import org.junit.Test;

import com.blackducksoftware.integration.hub.meta.MetaInformation;

public class ScanStatusToPollTest {

	@Test
	public void testScanStatusToPoll() {
		final String status1 = "fakeStatus1";
		final String href1 = "href1";
		final MetaInformation meta1 = new MetaInformation(null, href1, null);

		final String status2 = ScanStatus.COMPLETE.name();
		final String href2 = "href2";
		final MetaInformation meta2 = new MetaInformation(null,href2, null);

		final ScanStatusToPoll item1 = new ScanStatusToPoll(status1, meta1);
		final ScanStatusToPoll item2 = new ScanStatusToPoll(status2, meta2);
		final ScanStatusToPoll item3 = new ScanStatusToPoll(status1, meta1);

		assertEquals(status1, item1.getStatus());
		assertEquals(ScanStatus.UNKNOWN, item1.getStatusEnum());
		assertEquals(meta1, item1.get_meta());

		assertEquals(status2, item2.getStatus());
		assertEquals(ScanStatus.COMPLETE, item2.getStatusEnum());
		assertEquals(meta2, item2.get_meta());

		assertTrue(!item1.equals(item2));
		assertTrue(item1.equals(item3));

		EqualsVerifier.forClass(ScanStatusToPoll.class).suppress(Warning.STRICT_INHERITANCE).verify();

		assertTrue(item1.hashCode() != item2.hashCode());
		assertEquals(item1.hashCode(), item3.hashCode());

		final StringBuilder builder = new StringBuilder();
		builder.append("ScanStatusToPoll [status=");
		builder.append(status1);
		builder.append(", _meta=");
		builder.append(meta1);
		builder.append("]");

		assertEquals(builder.toString(), item1.toString());
	}

}
