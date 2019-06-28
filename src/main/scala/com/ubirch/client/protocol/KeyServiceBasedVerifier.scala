package com.ubirch.client.protocol

import java.security.{MessageDigest, NoSuchAlgorithmException, SignatureException}
import java.util.{Base64, UUID}

import com.typesafe.scalalogging.StrictLogging
import com.ubirch.client.keyservice.KeyService
import com.ubirch.client.util._
import com.ubirch.crypto.GeneratorKeyFactory
import com.ubirch.crypto.utils.Curve
import com.ubirch.protocol.ProtocolVerifier

class KeyServiceBasedVerifier(keyService: KeyService) extends ProtocolVerifier with StrictLogging {
  override def verify(uuid: UUID, data: Array[Byte], offset: Int, len: Int, signature: Array[Byte]): Boolean = {
    if (signature == null) throw new SignatureException("signature must not be null")
    logger.debug(s"DATA: d=${hexEncode(data)}")
    logger.debug(s"SIGN: s=${hexEncode(signature)}")

    keyService.getPublicKeys(uuid).headOption match {
      case Some(key) =>
        val pubKeyBytes = Base64.getDecoder.decode(key.pubKeyInfo.pubKey)
        key.pubKeyInfo.algorithm match {
          case "ECC_ED25519" | "Ed25519" =>
            // Ed25519 uses SHA512 hashed messages
            val digest: MessageDigest = MessageDigest.getInstance("SHA-512")
            digest.update(data, offset, len)
            val dataToVerify = digest.digest

            logger.debug(s"verifying ED25519: ${hexEncode(dataToVerify)}")
            GeneratorKeyFactory.getPubKey(pubKeyBytes, Curve.Ed25519).verify(dataToVerify, signature)
          case "ECC_ECDSA" | "ecdsa-p256v1" | "ECDSA" =>
            val dataToVerify = data.slice(offset, offset + len)

            logger.debug(s"verifying ECDSA: ${hexEncode(dataToVerify)}")
            GeneratorKeyFactory.getPubKey(pubKeyBytes, Curve.PRIME256V1).verify(dataToVerify, signature)
          case algorithm: String =>
            throw new NoSuchAlgorithmException(s"unsupported algorithm: $algorithm")
        }
      case None => throw new NoSuchElementException(s"Public key not found for deviceId: [$uuid]")
    }
  }
}
