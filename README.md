# VHostListenerAkamaiValidate
Akamai servers use special HTTP headers when they request HTTP-based streams from Wowza Streaming Engine™ applications that are running in HTTP Origin mode. The Akamai servers use these headers to validate the connection and to identify the connection as coming from an Akamai server. If the connection is valid, then it can be accepted. If the connection is invalid or rejected, then an appropriate HTTP response code is returned.

## Prerequisites
[Wowza Streaming Engine](https://www.wowza.com/products/streaming-engine) 4.0.0 or later is required to use the **AkamaiValidate** VHost Listener.

## Usage
A request is valid for 30 seconds and all requests are cached for 60 seconds. This ensures that a second request isn't made with the same values. Wowza Streaming Engine checks to see if the time in the data header is within 30 seconds of the server time. The clock on the server should be set by using Network Time Protocol (NTP) to eliminate any timing issues.

When a request path is invalid, Wowza Streaming Engine's default response is to pass the request to the default HTTP Provider to see if the path can be matched there. The default HTTP Provider would then return a 200 response. The configuration described in this article replaces the default HTTP Provider with a custom one that returns a 403 response.

## More resources
[Auth: Edge to Origin (Chapter 11 - Akamai Edge Server Configuration Guide)]("https://control.akamai.com/dl/customers/other/EDGESERV/ESConfigGuide-Customer.pdf#G11.1119545") (**Note:** You must have an Akamai account to access or download the guide from Akamai.)

[Wowza Streaming Engine Server-Side API Reference](https://www.wowza.com/resources/WowzaStreamingEngine_ServerSideAPI.pdf)

[How to extend Wowza Streaming Engine using the Wowza IDE](https://www.wowza.com/forums/content.php?759-How-to-extend-Wowza-Streaming-Engine-using-the-Wowza-IDE)

Wowza Media Systems™ provides developers with a platform to create streaming applications and solutions. See [Wowza Developer Tools](https://www.wowza.com/resources/developers) to learn more about our APIs and SDK.

To use the compiled version of this module, see [How to validate Akamai server connections with Akamai G2O authorization (VHostListenerAkamaiValidate)](https://staging.wowza.com/forums/content.php?651-How-to-validate-Akamai-server-connections-with-Akamai-G2O-authorization-%28VHostListenerAkamaiValidate%29).

## Contact
[Wowza Media Systems, LLC](https://www.wowza.com/contact)

## License
This code is distributed under the [Wowza Public License](https://github.com/WowzaMediaSystems/wse-plugin-akamaivalidate/blob/master/LICENSE.txt).
