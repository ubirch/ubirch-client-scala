package com.ubirch.client.keyservice

import java.util.UUID

import com.ubirch.client.keyservice.KeyService.PublicKey

trait KeyService {
  def getPublicKeys(uuid: UUID): List[PublicKey]
}

object KeyService {
  case class PublicKey(pubKeyInfo: PublicKeyInfo)
  case class PublicKeyInfo(pubKey: String, algorithm: String)
}
