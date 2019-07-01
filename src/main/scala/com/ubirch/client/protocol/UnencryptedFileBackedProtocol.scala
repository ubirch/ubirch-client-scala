package com.ubirch.client.protocol

import java.nio.file.Path

import com.ubirch.client.keyservice.UnencryptedFileKeyProvider
import com.ubirch.protocol.Protocol


object UnencryptedFileBackedProtocol {
  def apply(file: Path): Protocol = {
    val ks = new UnencryptedFileKeyProvider(file)
    new CustomProtocol(new DefaultProtocolSigner(ks.getPrivateKey), new DefaultProtocolVerifier(ks))
  }
}
