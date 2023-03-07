package com.ubirch.client.protocol

import com.ubirch.client.keyservice.PublicKeyProvider
import com.ubirch.crypto.GeneratorKeyFactory
import com.ubirch.crypto.utils.Curve
import org.mockito.Mockito
import org.scalatest.flatspec.AnyFlatSpec

import java.util.{Base64, UUID}
class MultiKeyProtocolVerifierTest extends AnyFlatSpec {

  val publicKeyProviderMock = Mockito.mock(classOf[PublicKeyProvider])
  val multiKeyProtocolVerifier = new MultiKeyProtocolVerifier(publicKeyProviderMock)
  val trackleDeviceId = UUID.fromString("d3407cca-cbfa-474d-8d57-433643eb1e58")
  val dataToVerify =
    Base64.getDecoder.decode("liPEENNAfMrL+kdNjVdDNkPrHljEQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABWxEAVN4ktmtTQ9D+e8BWeQ8BJbdZJE1ehiunTTYqGpxRFG2cKQRmSgY6h1fOahgZROjtggPM+1ke7gKIqt2iCOSfX")
  val signature =
    Base64.getDecoder.decode("VSGRCSdIXozCAc8V+4nbSUnguabUrJw2LKYLqQtlebAKJLMPPhfY0mautQm38yRvjamFZngZyPXREPZ5dovxBA==")
  val pubKeyBytesHex = "62e67af111cf18c72441fd7191ec4853711642d385433da2ea4155b99bf68f48"
  val pubKey = GeneratorKeyFactory.getPubKey(pubKeyBytesHex, Curve.Ed25519)

  "MultiKeyProtocolVerifier" should "succeed verify hashed trackle msg" in {
    assert(multiKeyProtocolVerifier.verifySingle(
      trackleDeviceId,
      dataToVerify,
      0,
      0,
      signature,
      pubKey))
  }

}
