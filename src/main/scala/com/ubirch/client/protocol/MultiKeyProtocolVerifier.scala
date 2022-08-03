package com.ubirch.client.protocol

import com.typesafe.scalalogging.StrictLogging
import com.ubirch.client.keyservice.PublicKeyProvider
import com.ubirch.client.util._
import com.ubirch.crypto.PubKey
import com.ubirch.protocol.ProtocolVerifier
import com.ubirch.protocol.codec.MsgPackProtocolDecoder

import java.security.{MessageDigest, SignatureException}
import java.util
import java.util.UUID
import scala.util.Try

class MultiKeyProtocolVerifier(keyService: PublicKeyProvider) extends ProtocolVerifier with StrictLogging {

  val msgPackProtocolDecoder = MsgPackProtocolDecoder.getDecoder
  def verifySingle(
    uuid: UUID,
    data: Array[Byte],
    offset: Int,
    len: Int,
    signature: Array[Byte],
    key: PubKey): Boolean = {
    key.getPublicKey.getAlgorithm match {
      case "ECC_ED25519" | "Ed25519" =>

      // hashedTrackleMsg has already hashed signed with SHA512; fallback to regular verification if needed
      if(msgPackProtocolDecoder.isSignedOfHashedTrackleMsgType(data)) {
          val payload = util.Arrays.copyOfRange(data, data.length - 64, data.length);
          if (key.verify(payload, signature)) {
            logger.debug(s"verifying ED25519: true ${hexEncode(payload)}")
            return true
          }
        }
        // Ed25519 uses SHA512 hashed messages
        val digest = MessageDigest.getInstance("SHA-512")
        digest.update(data, offset, len)
        val dataToVerify = digest.digest
        val ok = key.verify(dataToVerify, signature)
        logger.debug(s"verifying ED25519: $ok ${hexEncode(dataToVerify)}")
        ok

      case "ECC_ECDSA" | "ecdsa-p256v1" | "ECDSA" =>
        val dataToVerify = data.slice(offset, offset + len)

        val ok = Try(key.verify(dataToVerify, signature))
          .recover {
            case e: SignatureException =>
              logger.debug("Trying with Signature PlainEncoding", e.getMessage)
              key.setSignatureAlgorithm("SHA256WITHPLAIN-ECDSA")
              key.verify(dataToVerify, signature)
          }.get
        logger.debug(s"verifying ECDSA: $ok ${hexEncode(dataToVerify)}")
        ok
      case algorithm: String =>
        logger.warn(s"$uuid has key with unsupported algorithm: $algorithm")
        false
    }
  }

  def verifyMulti(uuid: UUID, data: Array[Byte], offset: Int, len: Int, signature: Array[Byte]): Option[PubKey] = {
    if (signature == null) throw new SignatureException("signature must not be null")
    logger.debug(s"DATA: d=${hexEncode(data)} offset=$offset len=$len")
    logger.debug(s"SIGN: s=${hexEncode(signature)}")

    val keys = keyService.getPublicKey(uuid)
    if (keys.isEmpty) {
      throw new NoSuchElementException(s"Public key not found for deviceId: [$uuid]")
    }

    logger.debug(s"found ${keys.size} valid public keys")
    keys.find(verifySingle(uuid, data, offset, len, signature, _))
  }

  override def verify(uuid: UUID, data: Array[Byte], offset: Int, len: Int, signature: Array[Byte]): Boolean = {
    verifyMulti(uuid, data,offset, len, signature).isDefined
  }
}
