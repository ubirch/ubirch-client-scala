package com.ubirch.client.protocol

import com.ubirch.crypto.GeneratorKeyFactory
import com.ubirch.crypto.utils.Curve

import org.scalatest.flatspec.AnyFlatSpec

import java.util.UUID
import scala.util.Random

class SignerTest extends AnyFlatSpec {

  "DefaultProtocolSigner" should "work with EDDSA keys" in {
    val key = GeneratorKeyFactory.getPrivKey(Curve.Ed25519)
    val ps = new DefaultProtocolSigner(_ => Some(key))
    val data = new Array[Byte](255)
    Random.nextBytes(data)
    val uuid = UUID.randomUUID()
    val signature = ps.sign(uuid, data, 0, data.length)
    // the above should just not throw

    val verifier = new DefaultProtocolVerifier((_: UUID) =>
      List(GeneratorKeyFactory.getPubKey(key.getRawPublicKey, Curve.Ed25519))
    )

    val verification = verifier.verify(uuid, data, 0, data.length, signature)
    assert(verification)

  }

  it should "work with ECDSA keys" in {
    val key = GeneratorKeyFactory.getPrivKey(Curve.PRIME256V1)
    val ps = new DefaultProtocolSigner(_ => Some(key))
    val data = new Array[Byte](255)
    Random.nextBytes(data)
    val uuid = UUID.randomUUID()

    val signature = ps.sign(uuid, data, 0, data.length)
    // the above should just not throw

    val verifier = new DefaultProtocolVerifier((_: UUID) =>
      List(GeneratorKeyFactory.getPubKey(key.getRawPublicKey, Curve.PRIME256V1))
    )

    val verification = verifier.verify(uuid, data, 0, data.length, signature)
    assert(verification)

  }
}
