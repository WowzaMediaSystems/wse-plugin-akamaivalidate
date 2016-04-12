/**
 * This code and all components (c) Copyright 2006 - 2016, Wowza Media Systems, LLC.  All rights reserved.
 * This code is licensed pursuant to the Wowza Public License version 1.0, available at www.wowza.com/legal.
 */
package com.wowza.wms.plugin.akamaivalidate;

import java.security.Key;
import java.util.HashMap;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.wowza.util.Base64;
import com.wowza.util.DebugUtils;
import com.wowza.util.MD5DigestUtils;
import com.wowza.util.StringUtils;
import com.wowza.wms.amf.AMFDataList;
import com.wowza.wms.application.WMSProperties;
import com.wowza.wms.client.IClient;
import com.wowza.wms.logging.WMSLogger;
import com.wowza.wms.logging.WMSLoggerFactory;
import com.wowza.wms.logging.WMSLoggerIDs;
import com.wowza.wms.request.RequestFunction;
import com.wowza.wms.server.RtmpRequestMessage;
import com.wowza.wms.vhost.HostPort;
import com.wowza.wms.vhost.IVHost;
import com.wowza.wms.vhost.IVHostHTTPStreamerRequestValidator;
import com.wowza.wms.vhost.IVHostNotify;
import com.wowza.wms.vhost.VHost;

public class VHostListenerAkamaiValidate implements IVHostNotify
{
	public static final String CLASS_NAME = "AkamaiValidator";
	public static final String PROP_NAME_PREFIX = "akamaiValidator";

	public static final String AUTH_TYPE_VIA = "via";
	public static final String AUTH_TYPE_UA = "userAgent";
	public static final String AUTH_TYPE_COOKIE = "cookie";
	public static final String AUTH_TYPE_SIGNATURE = "signature";
	public static final String AUTH_VALUE_VIA = "1.1 akamai.net (ghost) (AkamaiGHost)";
	public static final String AUTH_VALUE_UA = "Akamai Edge";
	public static final String AUTH_SIGNATURE_DATA_HEADER = "X-Akamai-G2O-Auth-Data";
	public static final String AUTH_SIGNATURE_SIGN_HEADER = "X-Akamai-G2O-Auth-Sign";
	public static final String CHAR_ENCODE_STR = "UTF-8";

	private static final String HMAC_MD5_ALGORITHM = "HmacMD5";
    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
    private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

	private static final int AUTH_SIGNATURE_VERSION_1 = 1;
	private static final int AUTH_SIGNATURE_VERSION_2 = 2;
	private static final int AUTH_SIGNATURE_VERSION_3 = 3;
	private static final int AUTH_SIGNATURE_VERSION_4 = 4;
	private static final int AUTH_SIGNATURE_VERSION_5 = 5;

	private class AkamaiValidator implements IVHostHTTPStreamerRequestValidator
	{
		private IVHost vhost;
		private String authType;
		private String viaValue;
		private String authCookie;
		private String authDataHeaderName;
		private String authSignHeaderName;
		private String authSecret;
		private String authNonceSecrets;
		private Map<String, String> secrets = new HashMap<String, String>();
		private SortedMap<Long, String> pastData = new TreeMap<Long, String>();
		private WMSLogger logger;
		
		private String pathPattern = "";
		private boolean validateMatchingPaths = true;
		private boolean checkViaOnAllRequests;
		private boolean debugLog;

		private AkamaiValidator(IVHost vhost)
		{
			this.vhost = vhost;
			this.logger = WMSLoggerFactory.getLoggerObj(vhost);
			WMSProperties props = vhost.getProperties();
			this.pathPattern = props.getPropertyStr(PROP_NAME_PREFIX + "PathPattern", pathPattern);
			this.validateMatchingPaths = props.getPropertyBoolean(PROP_NAME_PREFIX + "ValidateMatchingPaths", validateMatchingPaths);
			this.authType = props.getPropertyStr(PROP_NAME_PREFIX + "AuthType", AUTH_TYPE_VIA);
			this.checkViaOnAllRequests = props.getPropertyBoolean(PROP_NAME_PREFIX + "CheckViaHeader", false);
			this.viaValue = props.getPropertyStr(PROP_NAME_PREFIX + "ViaValue", AUTH_VALUE_VIA);
			this.authCookie = props.getPropertyStr(PROP_NAME_PREFIX + "AuthCookie");
			this.authDataHeaderName = props.getPropertyStr(PROP_NAME_PREFIX + "AuthDataHeader", AUTH_SIGNATURE_DATA_HEADER);
			this.authSignHeaderName = props.getPropertyStr(PROP_NAME_PREFIX + "AuthSignHeader", AUTH_SIGNATURE_SIGN_HEADER);
			this.authSecret = props.getPropertyStr(PROP_NAME_PREFIX + "AuthSecret");
			this.authNonceSecrets = props.getPropertyStr(PROP_NAME_PREFIX + "AuthNonceSecrets");
			if (this.authNonceSecrets != null)
			{
				String[] nonceSecrets = this.authNonceSecrets.split("\\|");
				for (String nonceSecret : nonceSecrets)
				{
					String[] parts = nonceSecret.trim().split(",");
					if (parts.length == 2)
					{
						secrets.put(parts[0].trim(), parts[1].trim());
					}
				}
			}
			this.debugLog = props.getPropertyBoolean(PROP_NAME_PREFIX + "DebugLog", false);
			if (logger.isDebugEnabled())
				this.debugLog = true;

			logger.info(CLASS_NAME + "started: " + "[authType: " + this.authType + ", checkViaHeader: " + this.checkViaOnAllRequests + ", viaValue: " + this.viaValue + ", authCookie: " + this.authCookie + ", authDataHeader: " + this.authDataHeaderName + ", authSignHeader: "
					+ this.authSignHeaderName + ", authSecret: " + this.authSecret + ", authNonceSecrets: " + this.authNonceSecrets + ", debugLog: " + this.debugLog + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
		}

		@Override
		public boolean validateHTTPStreamerRequest(RtmpRequestMessage request, HostPort hostPort, String path)
		{
			// check default validator first.
			boolean valid = ((VHost)vhost).validateHTTPStreamerRequest(request, hostPort, path);
			if (valid)
			{
				String reqStr = new String(request.getBody().array());
				if (debugLog)
					logger.info(CLASS_NAME + ".validateHTTPStreamerRequest [req: " + reqStr + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
				path = getPathFromRequest(reqStr);
				if (checkPath(path))
				{
					while (true)
					{
						if (this.authType.equalsIgnoreCase(AUTH_TYPE_VIA))
						{
							valid = doViaAuth(reqStr);
							break;
						}
						if (this.authType.equalsIgnoreCase(AUTH_TYPE_UA))
						{
							valid = doUAAuth(reqStr);
							break;
						}
						if (this.authType.equalsIgnoreCase(AUTH_TYPE_COOKIE))
						{
							valid = doCookieAuth(reqStr);
							break;
						}
						if (this.authType.equalsIgnoreCase(AUTH_TYPE_SIGNATURE))
						{
							valid = doSignatureAuth(reqStr, path);
							break;
						}
						break;
					}
				}
			}
			else
			{
				if (debugLog)
					logger.warn(CLASS_NAME + ".validateHTTPStreamerRequest failed path check [path: " + path + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
			}
			return valid;
		}

		private String getPathFromRequest(String request)
		{
			String path = "";
			request = request.replace("\r\n", "\n").replace("\r", "\n");
            String[] lines = request.split("\n");
            if (lines.length > 0)
            {
            	String[] header0 = lines[0].split(" ");
            	if(header0.length > 1)
            		path = header0[1];
            }
			return path;
		}

		private boolean checkPath(String path)
		{
			if(debugLog)
				logger.info(CLASS_NAME + ".checkPath checking [path: " + path + ", pathPattern: " + pathPattern.trim() + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
			boolean match = false;
			try
			{
				while (true)
				{
					if(StringUtils.isEmpty(pathPattern))
					{
						if(debugLog)
							logger.info(CLASS_NAME + ".checkPath pathPattern is empty. return true. [path: " + path + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
						return true;
					}
					if (pathPattern.equals("*"))
					{
						if(debugLog)
							logger.info(CLASS_NAME + ".checkPath pathPattern = *. [path: " + path + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
						match = true;
						break;
					}
					if(Pattern.matches(pathPattern.trim(), path))
					{
						if(debugLog)
							logger.info(CLASS_NAME + ".checkPath match found. [path: " + path + ", pathPattern: " + pathPattern.trim() + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
						match = true;
						break;
					}
					break;
				}
			}
			catch (Exception e)
			{
				logger.error(CLASS_NAME + ".checkPath Exception: ", e);
			}
			
			if(debugLog)
				logger.info(CLASS_NAME + ".checkPath [path: " + path + ", pathPattern: " + pathPattern.trim() + ", match: " + match + ", validateMatchingPaths: " + validateMatchingPaths + ", return: " + (match == validateMatchingPaths) + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
			return match == validateMatchingPaths;
		}

		private boolean doViaAuth(String req)
		{
			String via = getHeader(req, "Via");
			if (via != null && via.contains(this.viaValue))
				return true;
			if (debugLog)
				logger.warn(CLASS_NAME + ".doViaAuth failed Via check [header: " + via + ", expected: " + this.viaValue + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
			return false;
		}

		private boolean doUAAuth(String req)
		{
			if (this.checkViaOnAllRequests && !doViaAuth(req))
				return false;
			String userAgent = getHeader(req, "User-Agent");
			if (userAgent != null && userAgent.equals(AUTH_VALUE_UA))
				return true;
			if (debugLog)
				logger.warn(CLASS_NAME + ".doUAAuth failed UA check [header: " + userAgent + ", expected: " + AUTH_VALUE_UA + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
			return false;
		}

		private boolean doCookieAuth(String req)
		{
			if (this.checkViaOnAllRequests && !doViaAuth(req))
			{
				return false;
			}
			if (StringUtils.isEmpty(this.authCookie))
			{
				if (debugLog)
					logger.warn(CLASS_NAME + ".doCookieAuth cookie not set in properties", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
				return false;
			}
			String cookie = getHeader(req, "Cookie");
			if (cookie != null && cookie.contains(this.authCookie))
				return true;
			if (debugLog)
				logger.warn(CLASS_NAME + ".doCookieAuth failed UA check [header: " + cookie + ", expected: " + this.authCookie + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
			return false;
		}

		private boolean doSignatureAuth(String req, String path)
		{
			if (this.checkViaOnAllRequests && !doViaAuth(req))
			{
				return false;
			}
			if (StringUtils.isEmpty(this.authSecret) && secrets.size() == 0)
			{
				if (debugLog)
					logger.warn(CLASS_NAME + ".doSignatureAuth failed. no secrets set in properties", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
				return false;
			}
			String data = getHeader(req, this.authDataHeaderName);
			String signature = getHeader(req, this.authSignHeaderName);
			if (StringUtils.isEmpty(data) || StringUtils.isEmpty(signature))
			{
				if (debugLog)
					logger.warn(CLASS_NAME + ".doSignatureAuth failed. data and / or signature header missing [data: " + data + ", signature: " + signature + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
				return false;
			}

			long now = System.currentTimeMillis();
			// the data string is stored for at least 60 secs so it cannot be reused.  After that time, it will fail the time test so is removed here.
			while (!pastData.isEmpty() && pastData.firstKey() < now - 60000)
			{
				long key = pastData.firstKey();
				String oldData = pastData.remove(key);
				if (debugLog)
					logger.info(CLASS_NAME + ".doSignatureAuth delete old data [now: " + now + ", key: " + key + ", data: " + oldData + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
			}
			if (pastData.containsValue(data))
			{
				if (debugLog)
					logger.warn(CLASS_NAME + ".doSignatureAuth failed. data already used [data: " + data + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
				return false;
			}

			byte[] hash = null;
			boolean valid = false;
			try
			{
				String[] dataArray = data.split(",");
				if (dataArray.length != 6)
				{
					if (debugLog)
						logger.warn(CLASS_NAME + ".doSignatureAuth failed. data too small. expected 6 values [data: " + data + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
					return false;
				}
				int version;
				try
				{
					version = Integer.parseInt(dataArray[0].trim());
				}
				catch (Exception e)
				{
					if (debugLog)
						logger.warn(CLASS_NAME + ".doSignatureAuth failed. version should be a number [version: " + dataArray[0].trim() + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
					return false;
				}
				long time;
				try
				{
					time = Long.parseLong(dataArray[3].trim()) * 1000;
				}
				catch (Exception e)
				{
					if (debugLog)
						logger.warn(CLASS_NAME + ".doSignatureAuth failed. time should be a number [time: " + dataArray[3].trim() + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
					return false;
				}
				if (time < now - 30000 || time > now + 30000)
				{
					if (debugLog)
						logger.warn(CLASS_NAME + ".doSignatureAuth failed. time out of range [time: " + time + ", range: " + (now - 30000) + "-" + (now + 30000) + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
					return false;
				}
				String nonce = dataArray[5];
				if (!secrets.containsKey(nonce) && StringUtils.isEmpty(authSecret))
				{
					if (debugLog)
						logger.warn(CLASS_NAME + ".doSignatureAuth failed. no secret for nonce and no default secret [nonce: " + nonce + ", secrets: " + secrets.toString() + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
					return false;
				}

				String secret = secrets.containsKey(nonce) ? secrets.get(nonce) : this.authSecret;
				String values = secret + data + path;
				if (debugLog)
					logger.info(CLASS_NAME + ".doSignatureAuth building version " + version + " hash from [secret: " + secret + ", values: " + values + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
				byte[] valueBytes = values.getBytes(CHAR_ENCODE_STR);
				
				switch (version)
				{
				// version 1: MD5(key,data,sign-string)
				case AUTH_SIGNATURE_VERSION_1:
					hash = MD5DigestUtils.generateHashBytes(valueBytes);
					if (debugLog)
						logger.info(CLASS_NAME + ".doSignatureAuth building version " + version + " [hash: " + DebugUtils.formatBytesShort(hash) + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
					break;

				// version 2: MD5(key,MD5(key,data,sign-string))
				case AUTH_SIGNATURE_VERSION_2:
					byte[] secretBytes = secret.getBytes(CHAR_ENCODE_STR);
					byte[] first = MD5DigestUtils.generateHashBytes(valueBytes);
					byte[] second = new byte[secretBytes.length + first.length];
					System.arraycopy(secretBytes, 0, second, 0, secretBytes.length);
					System.arraycopy(first, 0, second, secretBytes.length, first.length);
					hash = MD5DigestUtils.generateHashBytes(second);
					if (debugLog)
					{
						logger.info(CLASS_NAME + ".doSignatureAuth building version " + version + " [firstPass: " + DebugUtils.formatBytesShort(first) + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
						logger.info(CLASS_NAME + ".doSignatureAuth building version " + version + " [secretBytes: " + DebugUtils.formatBytesShort(secretBytes) + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
						logger.info(CLASS_NAME + ".doSignatureAuth building version " + version + " [secondBytes: " + DebugUtils.formatBytesShort(second) + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
						logger.info(CLASS_NAME + ".doSignatureAuth building version " + version + " [hash: " + DebugUtils.formatBytesShort(hash) + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
					}
					break;

				// version 3: MD5-HMAC(key, data, sign-string)
				case AUTH_SIGNATURE_VERSION_3:
				case AUTH_SIGNATURE_VERSION_4:
				case AUTH_SIGNATURE_VERSION_5:
					String algorithm = HMAC_MD5_ALGORITHM;
					if (version == AUTH_SIGNATURE_VERSION_4)
						algorithm = HMAC_SHA1_ALGORITHM;
					if (version == AUTH_SIGNATURE_VERSION_5)
						algorithm = HMAC_SHA256_ALGORITHM;
					
					Key key = new SecretKeySpec(secret.getBytes(CHAR_ENCODE_STR), algorithm);
					if (debugLog)
						logger.info(CLASS_NAME + ".doSignatureAuth building version " + version + "create key [algorithm: " + algorithm + ", sectet: " + DebugUtils.formatBytesShort(secret.getBytes(CHAR_ENCODE_STR)) + ", key: " + DebugUtils.formatBytesShort(key.getEncoded()) + "]", WMSLoggerIDs.CAT_vhost,
								WMSLoggerIDs.EVT_comment);
					Mac mac = Mac.getInstance(algorithm);
					mac.init(key);
					mac.update(data.getBytes(CHAR_ENCODE_STR));
					if (debugLog)
						logger.info(CLASS_NAME + ".doSignatureAuth building version " + version + "add data [data: " + DebugUtils.formatBytesShort(data.getBytes(CHAR_ENCODE_STR)) + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
					mac.update(path.getBytes(CHAR_ENCODE_STR));
					if (debugLog)
						logger.info(CLASS_NAME + ".doSignatureAuth building version " + version + "add path [path: " + DebugUtils.formatBytesShort(path.getBytes(CHAR_ENCODE_STR)) + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
					hash = mac.doFinal();
					if (debugLog)
						logger.info(CLASS_NAME + ".doSignatureAuth building version " + version + "get hash [hash: " + DebugUtils.formatBytesShort(hash) + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
					break;
					
				default:
					if (debugLog)
						logger.warn(CLASS_NAME + ".doSignatureAuth building version " + version + "not supported.", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
					break;
				}
			}
			catch (Exception e)
			{
				logger.error(CLASS_NAME + ".doSignatureAuth failed with exception: " + e.getMessage(), e);
			}
			if (hash != null)
			{
				String b64 = Base64.encodeBytes(hash);
				if (debugLog)
					logger.info(CLASS_NAME + ".doSignatureAuth b64 of hash: " + b64, WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
				if (signature.equals(b64))
				{
					if (debugLog)
					{
						logger.info(CLASS_NAME + ".doSignatureAuth b64 of hash matches signature [b64: " + b64 + ", signature: " + signature + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
						logger.info(CLASS_NAME + ".doSignatureAuth adding data to pastData [time: " + now + ", data: " + data + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
					}
					pastData.put(now, data);
					valid = true;
				}
				else
				{
					if (debugLog)
					{
						logger.warn(CLASS_NAME + ".doSignatureAuth failed. b64 of hash doesn't match signature [b64: " + b64 + ", signature: " + signature + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
						logger.warn(CLASS_NAME + ".doSignatureAuth failed. b64 of hash doesn't match signature [generated hash: " + DebugUtils.formatBytesShort(hash) + ", signature hash: " + DebugUtils.formatBytesShort(Base64.decode(signature)) + "]", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
					}
				}
			}
			else
			{
				if (debugLog)
					logger.warn(CLASS_NAME + ".doSignatureAuth failed. hash is null", WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
			}
			return valid;
		}

		private String getHeader(String req, String name)
		{
			String ret = null;
			req = req.replace("\r\n", "\n").replace("\r", "\n");
			String[] lines = req.split("\n");
			for (String line : lines)
			{
				if (debugLog)
					logger.info(CLASS_NAME + ".getHeader looking for header: " + name + ", line: " + line, WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
				if (StringUtils.isEmpty(line))
					continue;
				if (line.toLowerCase().startsWith(name.toLowerCase()))
				{
					int idx = line.indexOf(":");
					if (idx != -1)
					{
						try
						{
							ret = line.substring(idx + 1).trim();
							if (debugLog)
								logger.info(CLASS_NAME + ".getHeader found header: " + name + ", value: " + ret, WMSLoggerIDs.CAT_vhost, WMSLoggerIDs.EVT_comment);
						}
						catch (Exception e)
						{
						}
					}
					break;
				}
			}
			return ret;
		}
	}

	@Override
	public void onVHostCreate(IVHost vhost)
	{
	}

	@Override
	public void onVHostInit(IVHost vhost)
	{
		vhost.setHTTPStreamerRequestValidator(new AkamaiValidator(vhost));
	}

	@Override
	public void onVHostShutdownStart(IVHost vhost)
	{
	}

	@Override
	public void onVHostShutdownComplete(IVHost vhost)
	{
	}

	@Override
	public void onVHostClientConnect(IVHost vhost, IClient inClient, RequestFunction function, AMFDataList params)
	{
	}
}
