package com.ubirch.client.keyservice

import java.util.UUID

import org.scalatest.{FlatSpec, Matchers}

class HttpKeyServiceTest extends FlatSpec with Matchers {
  "HttpKeyService" should "fetch and properly deserialize public keys" ignore {
    // NOTE: port forward this address when running this test
    val ks = new HttpKeyService("http://localhost:8095")
    val keys = ks.getPublicKeys(UUID.fromString("8e78b5ca-6597-11e8-8185-c83ea7000e4d"))
    keys.size should equal (1)
    keys.head.getRawPublicKey should equal ("97f2897959cef314d7916edb8dff8eba613bbd7c412243c783ce7fb9501b0626")
    keys.head.getPublicKey.getAlgorithm should equal ("Ed25519")
  }
}
