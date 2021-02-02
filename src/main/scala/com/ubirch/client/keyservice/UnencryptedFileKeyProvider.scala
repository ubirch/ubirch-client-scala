package com.ubirch.client.keyservice

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, StandardOpenOption}
import java.util.UUID

import com.ubirch.client.util._
import com.ubirch.crypto.utils.Curve
import com.ubirch.crypto.{GeneratorKeyFactory, PrivKey, PubKey}
import org.apache.commons.codec.binary.Hex

import scala.collection.JavaConverters._

class UnencryptedFileKeyProvider(file: Path) extends PublicKeyProvider {
  override def getPublicKey(deviceUuid: UUID): List[PubKey] = {
    Files.readAllLines(file).iterator().asScala.map { line =>
      val Array(uuidString, algorithm, pubKeyBytesHex, _) = line.split(',')
      UUID.fromString(uuidString) -> GeneratorKeyFactory.getPubKey(pubKeyBytesHex, curveFromString(algorithm))
    }.collect { case (uuid, pubKey) if uuid == deviceUuid => pubKey }.toList
  }

  def getPrivateKey(deviceUuid: UUID): Option[PrivKey] = {
    val existing = Files.readAllLines(file).iterator().asScala.map { line =>
      val Array(uuidString, algorithm, _, privKeyBytesHex) = line.split(',')
      UUID.fromString(uuidString) -> GeneratorKeyFactory.getPrivKey(privKeyBytesHex, curveFromString(algorithm))
    }.collectFirst { case (uuid, privKey) if uuid == deviceUuid => privKey }

    existing match {
      case x@Some(_) => x
      case None =>
        val k = GeneratorKeyFactory.getPrivKey(Curve.PRIME256V1)

        val keyLineToSave = s"$deviceUuid,ECDSA,${Hex.encodeHexString(k.getRawPublicKey)},${Hex.encodeHexString(k.getRawPrivateKey)}\n"
          .getBytes(StandardCharsets.UTF_8)
        Files.write(file, keyLineToSave, StandardOpenOption.CREATE, StandardOpenOption.APPEND)

        Some(k)
    }
  }
}
