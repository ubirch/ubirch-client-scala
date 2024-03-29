package com.ubirch.client.keyservice

import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers

import java.util.UUID


class UbirchKeyServiceTest extends AnyFlatSpec with Matchers {
  "HttpKeyService" should "fetch and properly deserialize public keys" ignore {
    // NOTE: port forward this address when running this test
    val ks = new UbirchKeyService("http://localhost:8095")
    val keys = ks.getPublicKey(UUID.fromString("8e78b5ca-6597-11e8-8185-c83ea7000e4d"))
    keys.head.getRawPublicKey should equal ("97f2897959cef314d7916edb8dff8eba613bbd7c412243c783ce7fb9501b0626")
    keys.head.getPublicKey.getAlgorithm should equal ("Ed25519")
  }
}
