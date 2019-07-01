package com.ubirch.client.protocol

import java.security.{MessageDigest, NoSuchAlgorithmException, SignatureException}
import java.util.UUID

import com.typesafe.scalalogging.StrictLogging
import com.ubirch.client.keyservice.PublicKeyProvider
import com.ubirch.client.util._
import com.ubirch.protocol.ProtocolVerifier

class DefaultProtocolVerifier(keyService: PublicKeyProvider) extends ProtocolVerifier with StrictLogging {
  override def verify(uuid: UUID, data: Array[Byte], offset: Int, len: Int, signature: Array[Byte]): Boolean = {
    if (signature == null) throw new SignatureException("signature must not be null")
    logger.debug(s"DATA: d=${hexEncode(data)}")
    logger.debug(s"SIGN: s=${hexEncode(signature)}")

    keyService.getPublicKey(uuid) match {
      case Some(key) =>
        key.getPublicKey.getAlgorithm match {
          case "ECC_ED25519" | "Ed25519" =>
            // Ed25519 uses SHA512 hashed messages
            val digest: MessageDigest = MessageDigest.getInstance("SHA-512")
            digest.update(data, offset, len)
            val dataToVerify = digest.digest

            logger.debug(s"verifying ED25519: ${hexEncode(dataToVerify)}")
            key.verify(dataToVerify, signature)
          case "ECC_ECDSA" | "ecdsa-p256v1" | "ECDSA" =>
            val dataToVerify = data.slice(offset, offset + len)

            logger.debug(s"verifying ECDSA: ${hexEncode(dataToVerify)}")
            key.verify(dataToVerify, signature)
          case algorithm: String =>
            throw new NoSuchAlgorithmException(s"unsupported algorithm: $algorithm")
        }
      case None => throw new NoSuchElementException(s"Public key not found for deviceId: [$uuid]")
    }
  }
}
