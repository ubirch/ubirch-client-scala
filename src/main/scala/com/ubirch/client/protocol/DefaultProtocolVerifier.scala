package com.ubirch.client.protocol

import java.security.{MessageDigest, SignatureException}
import java.util.UUID

import com.typesafe.scalalogging.StrictLogging
import com.ubirch.client.keyservice.PublicKeyProvider
import com.ubirch.client.util._
import com.ubirch.crypto.PubKey
import com.ubirch.protocol.ProtocolVerifier

class DefaultProtocolVerifier(keyService: PublicKeyProvider) extends ProtocolVerifier with StrictLogging {
  override def verify(uuid: UUID, data: Array[Byte], offset: Int, len: Int, signature: Array[Byte]): Boolean = {
    if (signature == null) throw new SignatureException("signature must not be null")
    logger.debug(s"DATA: d=${hexEncode(data)} offset=$offset len=$len")
    logger.debug(s"SIGN: s=${hexEncode(signature)}")

    val keys = keyService.getPublicKey(uuid)
    if (keys.isEmpty) {
      throw new NoSuchElementException(s"Public key not found for deviceId: [$uuid]")
    }

    logger.debug(s"found ${keys.size} valid public keys")
    keys.exists { key: PubKey =>
      key.getPublicKey.getAlgorithm match {
        case "ECC_ED25519" | "Ed25519" =>
          // Ed25519 uses SHA512 hashed messages
          val digest: MessageDigest = MessageDigest.getInstance("SHA-512")
          digest.update(data, offset, len)
          val dataToVerify = digest.digest

          val ok = key.verify(dataToVerify, signature)
          logger.debug(s"verifying ED25519: $ok ${hexEncode(dataToVerify)}")
          ok
        case "ECC_ECDSA" | "ecdsa-p256v1" | "ECDSA" =>
          val dataToVerify = data.slice(offset, offset + len)

          val ok = key.verify(dataToVerify, signature)
          logger.debug(s"verifying ECDSA: $ok ${hexEncode(dataToVerify)}")
          ok
        case algorithm: String =>
          logger.warn(s"$uuid has key with unsupported algorithm: $algorithm")
          false
      }
    }
  }
}
