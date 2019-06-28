package com.ubirch.client.keyservice

import java.util.UUID

import com.ubirch.client.keyservice.KeyService.{PublicKey, PublicKeyInfo}
import org.scalatest.{FlatSpec, Matchers}

class HttpKeyServiceTest extends FlatSpec with Matchers {
  "HttpKeyService" should "fetch and properly deserialize public keys" ignore {
    // NOTE: port forward this address when running this test
    val ks = new HttpKeyService("http://localhost:8095")
    val keys = ks.getPublicKeys(UUID.fromString("e97e160c-6117-5b89-ac98-15aeb52655e0"))
    keys should equal (List(PublicKey(PublicKeyInfo("l/KJeVnO8xTXkW7bjf+OumE7vXxBIkPHg85/uVAbBiY=", "ECC_ED25519"))))
  }
}
