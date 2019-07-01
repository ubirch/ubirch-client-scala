package com.ubirch.client.keyservice

import java.nio.file.Files
import java.util.UUID

import org.scalatest.{FlatSpec, Matchers}

class UnencryptedFileKeyServiceTest extends FlatSpec with Matchers {
  "UnencryptedFileKeyService" should "get no public key if the underlying file is empty" in {
    val f = Files.createTempFile("keys", ".tmp.csv")

    val ks = new UnencryptedFileKeyService(f)
    ks.getPublicKeys(UUID.fromString("8e78b5ca-6597-11e8-8185-c83ea7000e4d")) should equal (List())

    Files.delete(f)
  }

  it should "get a public key after a private key is generated" in {
    val f = Files.createTempFile("keys", ".tmp.csv")

    val ks = new UnencryptedFileKeyService(f)
    ks.getPrivateKey(UUID.fromString("8e78b5ca-6597-11e8-8185-c83ea7000e4d"))

    ks.getPublicKeys(UUID.fromString("8e78b5ca-6597-11e8-8185-c83ea7000e4d")).size should equal (1)

    Files.delete(f)
  }

  it should "get no public keys if the underlying file is not empty, but doesn't contain an entry for this uuid" in {
    val f = Files.createTempFile("keys", ".tmp.csv")

    val ks = new UnencryptedFileKeyService(f)
    ks.getPrivateKey(UUID.fromString("deadbeef-dead-beef-dead-beefdeadbeef"))

    ks.getPublicKeys(UUID.fromString("8e78b5ca-6597-11e8-8185-c83ea7000e4d")) should equal (List())

    Files.delete(f)
  }
}
