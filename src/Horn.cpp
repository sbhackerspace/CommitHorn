#include "WifiNetworkData.h"
#include <math.h>
#include <user_config.h>
#include <Network/NtpClient.h>
#include <SmingCore/SmingCore.h>
#include <Sha/sha256.h>

#define BUTTON_PIN 0
#define LED_PIN 3

HttpClient gHttpClient;
HttpServer gServer;
NtpClient gNtpClient("pool.ntp.org", 30);

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
void nothingToSeeHere(HttpRequest& request, HttpResponse& response)
{
  response.sendString("Nothing to see here. Move along");
}

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
uint8_t getHexFromChar(char character)
{
  String safetyCheck("1234567890abcdef");
  if (safetyCheck.indexOf(character) == -1)
  {
    return 0;
  }
  if (character == 'a')
  {
    return 10;
  }
  else if (character == 'b')
  {
    return 11;
  }
  else if (character == 'c')
  {
    return 12;
  }
  else if (character == 'd')
  {
    return 13;
  }
  else if (character == 'e')
  {
    return 14;
  }
  else if (character == 'f')
  {
    return 15;
  }
  else
  {
    return atoi(&character);
  }
}

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
uint8_t getValue(char Left, char Right)
{
  return (getHexFromChar(Left) * 16) + getHexFromChar(Right);
}

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
bool isOneTimePasswordValid(
  const String& oneTimePassword,
  const String& nonce,
  const long secondsSinceEpoch)
{
	auto UnixTime = SystemClock.now().toUnixTime();
  Vector<uint8_t> nonceValues;
  for (int i = 0; i < nonce.length(); i+=2)
  {
    auto Value = getValue(nonce[i], nonce[i+1]);
    nonceValues.addElement(Value);
  }
  long tempTime = secondsSinceEpoch/10;
  Serial.print("time values = ");
  while(tempTime)
  {
    Serial.print(tempTime % 10);
    nonceValues.addElement(tempTime % 10);
    tempTime /= 10;
  }
  Serial.println();

  //Start Hmacing
  Sha256.initHmac(hmacKey, 15);
  Serial.print("nonceValues = ");
  for (int i = 0; i < nonceValues.size(); ++i)
  {
    Serial.print(nonceValues[i]);
    Serial.print(",");
    Sha256.write(nonceValues[i]);
  }
  Serial.println();
  auto hash = Sha256.resultHmac();
  String hashString;
  for (auto i = 0; i <32; ++i)
  {
    hashString += "0123456789abcdef"[hash[i]>>4];
    hashString += "0123456789abcdef"[hash[i]&0xf];
  }
  Serial.print("hashString = ");
  Serial.println(hashString);
  Serial.print("Unix Time = ");
  Serial.println(UnixTime);
  return
    oneTimePassword.equalsIgnoreCase(hashString) &&
    abs(UnixTime - secondsSinceEpoch < 3);
}

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
void fireDeLazers(HttpRequest& request, HttpResponse& response)
{
  String oneTimePassword = request.getPostParameter("otp");
  String nonce = request.getPostParameter("nonce");
  long secondsSinceEpoch = request.getPostParameter("time").toInt();

  if (isOneTimePasswordValid(oneTimePassword, nonce, secondsSinceEpoch))
  {
    Serial.println("FIRE DE LAZERZ");
  }
  else
  {
    Serial.println("nope");
  }
}

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
void startWebServer()
{
  Serial.println("Connected");
  gServer.listen(80);
  gServer.addPath("/", fireDeLazers);
  gServer.addPath("horn", fireDeLazers);

	Serial.println("\r\n=== WEB SERVER STARTED ===");
	Serial.println(WifiStation.getIP());
	Serial.println("==============================\r\n");
}

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
void init()
{
  //pinMode(LED_PIN, OUTPUT);

	WifiStation.enable(true);
	WifiStation.config(ssid, password);
  WifiAccessPoint.enable(false);

  Sha256.initHmac(hmacKey, 15);
  Serial.print("Key = ");
  for (int i = 0; i < 15; ++i)
  {
    Serial.print(hmacKey[i]);
    Serial.print(',');
  }
  Serial.println();
	WifiStation.waitConnection(startWebServer);
  //SystemClock.setTimeZone(-8);
}
