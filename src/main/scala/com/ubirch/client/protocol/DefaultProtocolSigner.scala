package com.ubirch.client.protocol

import java.security.{MessageDigest, NoSuchAlgorithmException}
import java.util.{NoSuchElementException, UUID}

import com.typesafe.scalalogging.StrictLogging
import com.ubirch.crypto.PrivKey
import com.ubirch.protocol.ProtocolSigner

class DefaultProtocolSigner(getPrivateKey: UUID => Option[PrivKey]) extends ProtocolSigner with StrictLogging {
  override def sign(uuid: UUID, data: Array[Byte], offset: Int, len: Int): Array[Byte] = {
    val key = getPrivateKey(uuid)
      .getOrElse(throw new NoSuchElementException(s"key for deviceId [$uuid] not found"))

    key.getPrivateKey.getAlgorithm match {
      case "ECC_ED25519" | "Ed25519" => preHashAndSign(key, data, offset, len)
      case "ECC_ECDSA" | "ecdsa-p256v1" | "ECDSA" => justSign(key, data, offset, len)
      case algorithm => throw new NoSuchAlgorithmException(s"unsupported algorithm: $algorithm")
    }
  }

  private def preHashAndSign(key: PrivKey, data: Array[Byte], offset: Int, len: Int): Array[Byte] = {
    val sha512 = MessageDigest.getInstance("SHA-512")
    sha512.update(data, offset, len)
    val bytesToSign = sha512.digest()

    key.sign(bytesToSign)
  }

  private def justSign(key: PrivKey, data: Array[Byte], offset: Int, length: Int): Array[Byte] = {
    val bytesToSign = data.slice(offset, offset + length)

    key.sign(bytesToSign)
  }
}
