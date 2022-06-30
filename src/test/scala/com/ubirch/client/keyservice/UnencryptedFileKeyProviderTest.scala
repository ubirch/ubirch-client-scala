package com.ubirch.client.keyservice

import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers

import java.nio.file.Files
import java.util.UUID


class UnencryptedFileKeyProviderTest extends AnyFlatSpec with Matchers {
  "UnencryptedFileKeyService" should "get no public key if the underlying file is empty" in {
    val f = Files.createTempFile("keys", ".tmp.csv")

    val ks = new UnencryptedFileKeyProvider(f)
    ks.getPublicKey(UUID.fromString("8e78b5ca-6597-11e8-8185-c83ea7000e4d")).isEmpty should be (true)

    Files.delete(f)
  }

  it should "get a public key after a private key is generated" in {
    val f = Files.createTempFile("keys", ".tmp.csv")

    val ks = new UnencryptedFileKeyProvider(f)
    ks.getPrivateKey(UUID.fromString("8e78b5ca-6597-11e8-8185-c83ea7000e4d"))

    ks.getPublicKey(UUID.fromString("8e78b5ca-6597-11e8-8185-c83ea7000e4d")).nonEmpty should be (true)

    Files.delete(f)
  }

  it should "get no public keys if the underlying file is not empty, but doesn't contain an entry for this uuid" in {
    val f = Files.createTempFile("keys", ".tmp.csv")

    val ks = new UnencryptedFileKeyProvider(f)
    ks.getPrivateKey(UUID.fromString("deadbeef-dead-beef-dead-beefdeadbeef"))

    ks.getPublicKey(UUID.fromString("8e78b5ca-6597-11e8-8185-c83ea7000e4d")).isEmpty should be (true)

    Files.delete(f)
  }

  it should "always return the same private key for a given uuid" in {
    val f = Files.createTempFile("keys", ".tmp.csv")

    val ks = new UnencryptedFileKeyProvider(f)
    val k1 = ks.getPrivateKey(UUID.fromString("8e78b5ca-6597-11e8-8185-c83ea7000e4d")).get
    val k2 = ks.getPrivateKey(UUID.fromString("8e78b5ca-6597-11e8-8185-c83ea7000e4d")).get

    k1.getRawPrivateKey should equal (k2.getRawPrivateKey)
    k1.getPrivateKey.getAlgorithm should equal (k2.getPrivateKey.getAlgorithm)

    Files.delete(f)
  }
}
