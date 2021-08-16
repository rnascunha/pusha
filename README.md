# Pusha

**Pusha** is a C implementation to make **Web Push** requests. The library aims to provide a easy interface that supplying all the necessary information, it will deal with all the complexity. As a result, it delivers the HTTP headers and payload encryptation necessary to make the HTTP request.

It's also avaiable 2 tools to assist:
* [genkey](#genkey) will generate a pair of *private*/*public* keys needed to send the push requests;
* [push](#push) is a tool to send the push requests via command line.

## Decendencies

**Pusha** depends of:

* [CMake](https://cmake.org/) - to build **Pusha**;
* [OpenSSL](https://www.openssl.org/);
* [ECEC](https://github.com/web-push-libs/ecec);
* C compiler;

## Build

To build, first download the code:

```bash
$ git clone --recursive https://github.com/rnascunha/pusha
$ cd pusha
```
Let's create a build directory and compile:

```bash
$ mkdir build
$ cd build

#Build and compile
$ cmake ..
$ cmake --build .
```
This will build the **Pusha** library (*libpusha.a* at linux). If you want to build the [tools](#tools) and/or the examples,
add the following arguments to the `cmake` command:

```
$ cmake -DWITH_TOOLS=1 -DWITH_EXAMPLES=1 ..
```
## Tools

> Build **pusha** with -DWITH_TOOLS=1 to compile the tools.

### genkey

This tool will create a pair of *private*/*public* key that is needed to make push requests. It prints the keys in base64 encoded, and also export in PEM format.

```bash
$ ./genkey -h
Usage:
	./genkey -h|[-p private_pem_file] [-u public_pem_file]
Where:
	-h	print this help message
	-p	output private key to pem file specified
	-u	output public key to pem file specified
```
The private key is used with **Pusha** at the backend itself, and the public key pair at your website. As example:

```bash
$ ./genkey -p priv.pem
Private: 3zDn2khtNBpZCAUjwBepiaVy3u6bbVKZwlFP3d3nUbo
Public: BKE67tSj-yFp3ZsRruJnEwiGxj8KMUkC_5gk_tjRtoVDBHBhvpPX8DgOSVZXkey2AM1pk1vzEd7hlk_-KOqV_Yw
```
This command will also create a *priv.pem* with the private key.
### push

This will allows you to send push notification at command line.

```bash
$ ./push -h
Usage:
	./push -h|(-p <pem_priv_file>|-b <base64_priv_key>) [-v]
		[-m <message>] [-e <expire_time_seconds>]
		[-o send|curl|print] [-l <ttl>]
		<sub> <p256dh> <auth> <endpoint>

Where:
	<sub>	vapid subscriber (e.g. mainto:email@company.com)
	<p256dh>	public server key (received at push subscription)
	<auth>	authentication secret (received at push subscription)
	<endpoint>	endpoint (received at push subscription)
	-v	verbose mode
	-h	this help message
	-p	pem file with EC private key (don't use with '-b')
	-b	base64 encoded private key (don't use with '-p')
	-e	seconds to expire time (default 12h, i.e 12 * 60 * 60)
	-o	set output type. Options: 'send' (default), 'curl' or 'print'
	-l	set http ttl value (default = 0)
	-m	message payload to send
```
Five arguments are mandatory:
* *-p <pem_priv_file>*|*-b <base64_priv_key>*: the private key (can be generate with the [genkey](#genkey) tool above);
* *sub* (subscriber): a information of contact. A URL or a email (e.g *mailto:email@company.com*);
* *p256dh*, *auth* and *endpoint*: this information is received when the user allows to receive a push notification. Your application is responsible to keep this information for each user. When the user subscribe, it will present to you a information in a JSON format, like this:

```JSON
{
	"endpoint":"https://fcm.googleapis.com/fcm/send/eAIof_7CKT0:APA91bGtHiknduwFFRTTHF59vT05bsduAR_uAhWCGSxU-D8O3wg7Km0cRF246956jg-DPTlUj8xgAJP1I6VJU_xJipbpGg6rS4_B8qC5yKhqalDbkSDPwZ87ki_P3RlskUb1BEKY6wI8",
	"expirationTime":null,
	"keys":{
		"p256dh":"BMkGGRuBBhQf8H2s_I2Xz2487IaKqmP9WW3YRbgfi7MS4HkgLo73ZnbVOe5OLNL7judxPtElktgCLwOMWxRDLyo",
		"auth":"0cFEpUxPVUWT8NlnKF5xSQ"
	}
}
```
The fields correspondence is direct. To send a push request with payload to the user with the above information:

```bash
$ ./push -v -p priv.pem maito:email@company.com BMkGGRuBBhQf8H2s_I2Xz2487IaKqmP9WW3YRbgfi7MS4HkgLo73ZnbVOe5OLNL7judxPtElktgCLwOMWxRDLyo 0cFEpUxPVUWT8NlnKF5xSQ https://fcm.googleapis.com/fcm/send/eAIof_7CKT0:APA91bGtHiknduwFFRTTHF59vT05bsduAR_uAhWCGSxU-D8O3wg7Km0cRF246956jg-DPTlUj8xgAJP1I6VJU_xJipbpGg6rS4_B8qC5yKhqalDbkSDPwZ87ki_P3RlskUb1BEKY6wI8 -m 'My first push message'
-------Arguments------
+ Subscribe: maito:email@company.com
+ pd256h: BMkGGRuBBhQf8H2s_I2Xz2487IaKqmP9WW3YRbgfi7MS4HkgLo73ZnbVOe5OLNL7judxPtElktgCLwOMWxRDLyo
+ auth: 0cFEpUxPVUWT8NlnKF5xSQ
+ expiration time: 1628852983
+ ttl: 0
+ output: send
+ endpoint: https://fcm.googleapis.com/fcm/send/eAIof_7CKT0:APA91bGtHiknduwFFRTTHF59vT05bsduAR_uAhWCGSxU-D8O3wg7Km0cRF246956jg-DPTlUj8xgAJP1I6VJU_xJipbpGg6rS4_B8qC5yKhqalDbkSDPwZ87ki_P3RlskUb1BEKY6wI8
+ host[26]: https://fcm.googleapis.com
+ payload: My first push message
----------------------
* Decoding subscription...
*+ Subscription decoded
* Generating VAPID token...
*+ VAPID token generated...
* Push request with payload
* Encoding push payload...
*+ Push payload encoded success...
* Making HTTP headers...
*+ HTTP headers created
* Creating output...
* Sending push request...
* Serializing request...
*+ Request serialized
* Searching for host fcm.googleapis.com
* Trying to connect to 2800:3f0:4004:809::200a
*+ Connected
*+ SSL connected using TLS_AES_256_GCM_SHA384
* Sending SSL packet
*+ SSL packet sent[853]
* Wating response...
*+ Received 602 bytes
*+ Web push request sent successfully
> HTTP response: 201 Created
```
Output with verbose mode on (-v).

> The **push** tool is a good source to learn how to use the **pusha** library. It construct the push request step by step using some "internal" structures, learning how to manipulate the library.
## Examples

> Build **pusha** with -DWITH_EXAMPLES=1 to compile the examples.

There is two examples that shows how to use the **Pusha** library. The examples will print the information as a HTTP request should be. Both examples begin importing the *private* key from a PEM file. The only diference is the interface used:
* *web_push*: call the **pusha_notify** function, that populates the *push_http_headers* and *push_payload* (if any payload is present);
* *web_push_http*: call the **pusha_notify_http** function, that populates the *http_header*;

The examples are equivalent, it only changes the structure that holds the values. The description of the function/structures can be checked at *pusha.h*, *pusha/web_push.h* and *pusha/http.h*.

## See also

* [RFC8030](https://datatracker.ietf.org/doc/html/rfc8030) - Generic Event Delivery Using HTTP Push;
* [RFC8292](https://datatracker.ietf.org/doc/html/rfc8292) - Voluntary Application Server Identification (VAPID) for Web Push;
* [JSON Web Token](https://jwt.io/);
* [Push codelabs](https://developers.google.com/web/fundamentals/codelabs/push-notifications) - It provides a web page to test the push notitication (but use **pusha** instead to send message :kissing_heart:). When it says *Application Server Keys*, is the public pair of the keys generated;
* [HTTP internals](https://blog.mozilla.org/services/2016/08/23/sending-vapid-identified-webpush-notifications-via-mozillas-push-service/) - good explanation of the how to generate/use keys and create the HTTP headers;
