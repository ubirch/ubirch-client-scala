package com.ubirch.client.keyservice

import java.util.UUID

import com.ubirch.crypto.PubKey


trait PublicKeyProvider {
  def getPublicKey(uuid: UUID): Option[PubKey]
}
