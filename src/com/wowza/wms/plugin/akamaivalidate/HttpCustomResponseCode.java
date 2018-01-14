/*
 * This code and all components (c) Copyright 2006 - 2018, Wowza Media Systems, LLC. All rights reserved.
 * This code is licensed pursuant to the Wowza Public License version 1.0, available at www.wowza.com/legal.
 */
package com.wowza.wms.plugin.akamaivalidate;

import com.wowza.wms.http.*;
import com.wowza.wms.vhost.*;

public class HttpCustomResponseCode extends HTTProvider2Base
{
	
	public void onHTTPRequest(IVHost vhost, IHTTPRequest req, IHTTPResponse resp)
	{
		if (!doHTTPAuthentication(vhost, req, resp))
			return;
		int responseCode = this.properties.getPropertyInt("responseCode", 403);
		resp.setResponseCode(responseCode);
	}
}
