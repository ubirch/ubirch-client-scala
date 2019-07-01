package com.ubirch.client.keyservice

import java.util.UUID

import com.ubirch.crypto.PubKey


trait KeyService {
  def getPublicKeys(uuid: UUID): List[PubKey]
}
