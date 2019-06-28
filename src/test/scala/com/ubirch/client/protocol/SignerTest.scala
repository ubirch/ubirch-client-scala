package com.ubirch.client.protocol

import java.util.UUID

import com.ubirch.crypto.GeneratorKeyFactory
import com.ubirch.crypto.utils.Curve
import org.scalatest.FlatSpec

import scala.util.Random

class SignerTest extends FlatSpec {
  "DefaultProtocolSigner" should "work with EDDSA keys" in {
    val key = GeneratorKeyFactory.getPrivKey(Curve.Ed25519)
    val ps = new DefaultProtocolSigner(_ => Some(key))
    val data = new Array[Byte](255)
    Random.nextBytes(data)
    ps.sign(UUID.randomUUID(), data, 0, data.length)

    // the above should just not throw
  }

  it should "work with ECDSA keys" in {
    val key = GeneratorKeyFactory.getPrivKey(Curve.PRIME256V1)
    val ps = new DefaultProtocolSigner(_ => Some(key))
    val data = new Array[Byte](255)
    Random.nextBytes(data)
    ps.sign(UUID.randomUUID(), data, 0, data.length)

    // the above should just not throw
  }
}
