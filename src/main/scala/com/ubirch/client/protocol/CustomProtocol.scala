package com.ubirch.client.protocol

import java.util.UUID

import com.ubirch.protocol.{Protocol, ProtocolMessage, ProtocolSigner, ProtocolVerifier}

import scala.collection.mutable

class CustomProtocol(signer: ProtocolSigner, verifier: ProtocolVerifier) extends Protocol {
  private val signatures = new mutable.HashMap[UUID, mutable.Buffer[Array[Byte]]]
  private var isSigningChainedMessage = false

  override def getLastSignature(uuid: UUID): Array[Byte] = signatures.get(uuid).flatMap(_.lastOption).orNull

  override def verify(uuid: UUID, data: Array[Byte], offset: Int, len: Int, signature: Array[Byte]): Boolean =
    verifier.verify(uuid, data, offset, len, signature)

  override def sign(uuid: UUID, data: Array[Byte], offset: Int, len: Int): Array[Byte] = {
    val signature = signer.sign(uuid, data, offset, len)
    if (isSigningChainedMessage) signatures.getOrElseUpdate(uuid, mutable.Buffer()) += signature
    signature
  }

  override def encodeSign(pm: ProtocolMessage, format: Protocol.Format): Array[Byte] = {
    if (pm.getVersion == ProtocolMessage.CHAINED) {
      isSigningChainedMessage = true
    }
    val res = super.encodeSign(pm, format)
    isSigningChainedMessage = false
    res
  }
}